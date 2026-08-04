"""FastAPI dashboard API + static UI."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import threading
import time
from dataclasses import fields
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.core.engine import ScanEngine
from app.core.providers import provider_for_kind, provider_metadata
from app.core.result_secrets import is_noise_env_key, normalize_result_secrets
from app.core.ssh_servers import (
    SshServer,
    SshServerStore,
    collect_metrics,
    install_deps,
    new_server_id,
    preflight_servers,
    public_server_dict,
)
from app.extractors.patterns import IGNORED_SECRET_KINDS
from app.core.uploads import (
    DIRECT_UPLOAD_BYTES,
    complete_chunk_upload,
    create_upload,
    delete_upload_file,
    get_chunk_upload_status,
    init_chunk_upload,
    preview_upload_items,
    read_upload_items,
    safe_download_path,
    write_upload_chunk,
)
from app.core.vuln_artifacts import classify_finding, detection_method, host_from_finding, is_vuln_worthy, write_vuln_artifacts
from app.storage.db import ScanStore
from app.storage.models import ScanConfig
from app.utils.dedupe import dedupe_findings, value_hash

ROOT = Path(__file__).resolve().parents[2]
UI_DIR = ROOT / "app" / "ui"
UPLOAD_DIR = ROOT / "output" / "uploads"
log = logging.getLogger("bb.api")

store = ScanStore(ROOT / "output" / "scans" / "scanner.db")
engine = ScanEngine(store=store, enable_cli_progress=False)
ssh_store = SshServerStore(ROOT / "output" / "ssh_servers.json")
LOG_LINE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<level>[A-Z]+)\]\s+\[(?P<module>[^\]]+)\]\s*(?P<message>.*)$"
)


def _is_useless_secret(kind: str, value: str) -> bool:
    from app.extractors.validators import (
        is_placeholder,
        is_useless_env_assignment,
        looks_like_js_expression,
    )
    from app.modules.base import _looks_like_credential_line

    kind_l = (kind or "").lower()
    value_s = (value or "").replace("\r", "").strip()
    if kind_l in IGNORED_SECRET_KINDS or kind_l.startswith("generic"):
        return True
    if kind_l in {"absolute_api", "base_url", "fetch_call", "joomla_absolute_api"}:
        return True
    # Legacy exploit dumps put bash_history timestamps / bare numbers into Results.
    if kind_l in {"exploit", "bash_history", "dotenv", "next_config", "wp_config", "config"} and not _looks_like_credential_line(value_s):
        return True
    if value_s.isdigit():
        return True
    # Legacy rows / env KV that still carry public Google keys or JWTs.
    if value_s.startswith("AIza"):
        return True
    if value_s.startswith("eyJ") and value_s.count(".") >= 2:
        return True
    if "google_api" in kind_l or kind_l == "jwt":
        return True
    if kind_l in {"stripe_test", "paystack", "emailjs", "sanity", "tencent", "aliyun"}:
        return True
    if value_s.lower().startswith("sk_test_"):
        return True
    if kind_l == "env" and "=" in value_s:
        env_key, env_rhs = value_s.split("=", 1)
        if is_noise_env_key(env_key.strip()):
            return True
        if env_rhs.strip().lower().startswith("sk_test_"):
            return True
    # Stored env rows are ``KEY=VALUE``; drop JS ternary / generic LHS noise
    # (e.g. ``key=method ?`` from minified map-plugin JS).
    if kind_l == "env" and is_useless_env_assignment(value_s):
        return True
    rhs = value_s.split("=", 1)[1] if kind_l == "env" and "=" in value_s else value_s
    if looks_like_js_expression(rhs) or is_placeholder(rhs):
        return True
    return False


def _format_credential_value(kind: str, value: Any) -> str:
    if value is None:
        return ""
    if kind == "smtp" and isinstance(value, dict):
        host = str(value.get("host") or "").strip()
        port = str(value.get("port") or "").strip()
        user = str(value.get("user") or "").strip()
        password = str(value.get("pass") or value.get("password") or "").strip()
        host_part = f"{host}:{port}" if host and port else host
        parts = [part for part in (host_part, user, password) if part]
        return " | ".join(parts)
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True)
    return str(value).strip()


def _credential_provider(kind: str, value: Any) -> str:
    provider_id = provider_for_kind(kind)
    if provider_id != "other":
        return provider_id
    if kind == "smtp" and isinstance(value, dict):
        host = str(value.get("host") or "").lower()
        if host:
            return provider_for_kind(host)
    if kind == "env" and isinstance(value, str) and "=" in value:
        from app.core.providers import classify_env_assignment

        key, rhs = value.split("=", 1)
        classified = classify_env_assignment(key.strip(), rhs.strip())
        if classified:
            return classified[0]
    return provider_id


def _index_credential(
    secret_index: dict[str, dict[str, Any]],
    provider_counts: dict[str, int],
    *,
    kind: str,
    value: Any,
    source_url: str,
    module: str,
    title: str,
    finding_id: str,
) -> None:
    display = _format_credential_value(kind, value)
    if not display:
        return
    if _is_useless_secret(kind, display):
        return
    provider_id = _credential_provider(kind, value)
    key = f"{provider_id}:{kind}:{value_hash(display)}"
    if key not in secret_index:
        secret_index[key] = {
            "kind": kind,
            "provider": provider_id,
            "value": display,
            "source_url": source_url,
            "sources": [source_url] if source_url else [],
            "occurrences": 1,
            "module": module,
            "title": title,
            "finding_id": finding_id,
        }
        provider_counts[provider_id] = provider_counts.get(provider_id, 0) + 1
        return
    item = secret_index[key]
    item["occurrences"] += 1
    if source_url and source_url not in item["sources"]:
        item["sources"].append(source_url)


def read_file_logs(
    output_dir: str | Path,
    *,
    level: Optional[str] = None,
    module: Optional[str] = None,
    limit: int = 500,
) -> list[dict[str, str]]:
    path = Path(output_dir) / "scan.log"
    if not path.is_file():
        return []
    rows: list[dict[str, str]] = []
    # Rotating logs are capped at 5 MB, so reading the active file is bounded.
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        match = LOG_LINE.match(line)
        if not match:
            continue
        item = match.groupdict()
        if level and item["level"] != level.upper():
            continue
        if module and item["module"] != module:
            continue
        rows.append(item)
    return rows[-max(1, min(limit, 5000)) :]


class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        with self._lock:
            self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        with self._lock:
            if ws in self.active:
                self.active.remove(ws)

    async def broadcast(self, message: dict[str, Any]) -> None:
        data = json.dumps(message)
        with self._lock:
            conns = list(self.active)
        dead = []
        for ws in conns:
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()
_loop: Optional[asyncio.AbstractEventLoop] = None
_RESULTS_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_RESULTS_CACHE_LOCK = threading.Lock()
_RESULTS_CACHE_TTL_SEC = 180.0
# Serve an expired payload while a background rebuild runs so Results does not
# block the UI for another full aggregation after TTL.
_RESULTS_STALE_GRACE_SEC = 900.0
_RESULTS_REFRESHING: set[str] = set()


def _results_cache_get(
    cache_key: str, *, allow_stale: bool = False
) -> tuple[Optional[dict[str, Any]], bool]:
    """Return ``(payload, is_stale)``. Fresh hits set ``is_stale=False``."""
    with _RESULTS_CACHE_LOCK:
        item = _RESULTS_CACHE.get(cache_key)
        if not item:
            return None, False
        expires_at, payload = item
        now = time.monotonic()
        if expires_at >= now:
            return payload, False
        if allow_stale and (now - expires_at) <= _RESULTS_STALE_GRACE_SEC:
            return payload, True
        _RESULTS_CACHE.pop(cache_key, None)
        return None, False


def _results_cache_set(cache_key: str, payload: dict[str, Any]) -> None:
    with _RESULTS_CACHE_LOCK:
        _RESULTS_CACHE[cache_key] = (time.monotonic() + _RESULTS_CACHE_TTL_SEC, payload)
        # Bound memory if many scans are viewed.
        if len(_RESULTS_CACHE) > 32:
            oldest = sorted(_RESULTS_CACHE.items(), key=lambda kv: kv[1][0])[:8]
            for key, _ in oldest:
                _RESULTS_CACHE.pop(key, None)


def _broadcast_threadsafe(message: dict[str, Any]) -> None:
    loop = _loop
    if not loop:
        return
    try:
        asyncio.run_coroutine_threadsafe(manager.broadcast(message), loop)
    except Exception:
        pass


engine.on_finding = lambda sid, f: _broadcast_threadsafe({"type": "finding", "scan_id": sid, "data": f})
engine.on_progress = lambda sid, p: _broadcast_threadsafe({"type": "progress", "scan_id": sid, "data": p})
engine.on_log = lambda sid, e: _broadcast_threadsafe({"type": "log", "scan_id": sid, "data": e})


class ScanCreate(BaseModel):
    targets: list[str] = Field(default_factory=list)
    targets_text: str = ""
    job_name: str = ""
    targets_upload_id: str = ""
    wordlist_upload_id: str = ""
    modules: list[str] = Field(
        default_factory=lambda: ["git", "js", "config", "path", "methods", "wordpress", "joomla", "react"]
    )
    threads: int = 20
    worker_processes: int = 1
    timeout: float = 8.0
    connect_timeout: float = 0.0
    retries: int = 2
    rate_limit_per_host: float = 50.0
    paths_mode: str = "merge"
    custom_paths: list[str] = Field(default_factory=list)
    scope_notes: str = ""
    verify_tls: bool = False
    # Always store full secret values so Results can show complete API keys
    # (not last-4 redaction). The create handler forces this False as well.
    redact_secrets: bool = False
    method_test_trace: bool = False
    verbose: bool = False
    exploit_enabled: bool = False
    exploit_command: str = "id"
    exploit_all: bool = False
    ssh_server_ids: list[str] = Field(default_factory=list)


class SshServerCreate(BaseModel):
    host: str
    port: int = 22
    username: str = "ubuntu"
    auth_type: str = "key"
    private_key: str = ""
    password: str = ""
    label: str = ""
    connect_ip: str = ""


class ChunkUploadInit(BaseModel):
    filename: str
    kind: str = "targets"
    total_size: int


def _scan_config_from_dict(data: dict[str, Any]) -> ScanConfig:
    known = {f.name for f in fields(ScanConfig)}
    payload = {k: v for k, v in data.items() if k in known}
    payload.setdefault("targets", [])
    payload.setdefault("custom_paths", [])
    return ScanConfig(**payload)


def _resume_scan(scan_id: str) -> dict[str, Any]:
    """Rebuild config from disk artifacts and continue from checkpoint."""
    if engine.is_active(scan_id):
        raise HTTPException(status_code=409, detail="scan is already running")
    row = store.get_scan(scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="scan not found")
    status = row.get("status") or ""
    if status == "completed":
        raise HTTPException(status_code=400, detail="scan already completed")
    if status in {"pending", "running", "stopping"} and engine.is_active(scan_id):
        raise HTTPException(status_code=409, detail="scan is already running")
    progress = row.get("progress") or {}
    total = int(progress.get("total") or (row.get("config") or {}).get("target_count") or 0)
    done = int(progress.get("done") or 0) + int(progress.get("failed") or 0)
    if total and done >= total and status == "completed":
        raise HTTPException(status_code=400, detail="scan already completed")
    cfg_dict = store.rebuild_scan_config(scan_id)
    if not cfg_dict:
        raise HTTPException(status_code=400, detail="could not rebuild scan config")
    if not cfg_dict.get("targets_path") and not cfg_dict.get("targets"):
        raise HTTPException(status_code=400, detail="missing targets snapshot for resume")
    cfg = _scan_config_from_dict(cfg_dict)
    cfg.scan_id = scan_id
    store.update_status(scan_id, "pending")
    try:
        engine.start_async(cfg)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"id": scan_id, "status": "running", "resumed": True}


def create_app() -> FastAPI:
    app = FastAPI(title="BB Scanner", version="1.0.0")
    app.add_middleware(GZipMiddleware, minimum_size=1024, compresslevel=5)

    static_dir = UI_DIR / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.on_event("startup")
    async def _startup() -> None:
        global _loop
        _loop = asyncio.get_running_loop()
        # Worker threads do not survive a service restart. Mark orphans stopped,
        # then auto-resume incomplete ones from their durable checkpoints so a
        # reboot does not force operators to start from target 0 again.
        orphan_ids: list[str] = []
        for scan in store.list_scans(limit=1000, compact=True):
            if scan.get("status") in {"pending", "running", "stopping"} and not engine.is_active(scan["id"]):
                store.update_status(scan["id"], "stopped")
                orphan_ids.append(scan["id"])
        # One-time shrink of legacy summary_json rows that still embed the full
        # target list (those alone made /api/scans compact responses >1MB).
        try:
            store.slim_stored_summaries()
        except Exception:
            pass
        for scan_id in orphan_ids:
            row = store.get_scan(scan_id, compact=True) or {}
            progress = row.get("progress") or {}
            total = int(progress.get("total") or (row.get("config") or {}).get("target_count") or 0)
            finished = int(progress.get("done") or 0) + int(progress.get("failed") or 0)
            if total and finished >= total:
                continue
            try:
                await asyncio.to_thread(_resume_scan, scan_id)
                log.info("Auto-resumed interrupted scan %s after restart", scan_id)
            except HTTPException as exc:
                log.warning("Could not auto-resume scan %s: %s", scan_id, exc.detail)
            except Exception as exc:
                log.warning("Could not auto-resume scan %s: %s", scan_id, exc)

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        html = (UI_DIR / "templates" / "index.html").read_text(encoding="utf-8")
        # Bust browser caches whenever JS/CSS change — a stale app.js that still
        # bound removed Results DOM nodes was crashing init() and freezing tabs.
        asset_version = "1"
        try:
            asset_version = str(
                int(max(
                    (UI_DIR / "static" / "js" / "app.js").stat().st_mtime,
                    (UI_DIR / "static" / "css" / "app.css").stat().st_mtime,
                ))
            )
        except Exception:
            pass
        html = html.replace("__ASSET_VERSION__", asset_version)
        return HTMLResponse(
            html,
            headers={"Cache-Control": "no-store, max-age=0"},
        )

    @app.get("/api/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/api/scans")
    async def create_scan(body: ScanCreate) -> dict[str, Any]:
        targets = list(body.targets)
        if body.targets_text:
            targets.extend([ln.strip() for ln in body.targets_text.splitlines() if ln.strip()])
        targets = list(dict.fromkeys(targets))
        targets_upload: Optional[dict[str, Any]] = None
        if body.targets_upload_id:
            targets_upload = store.get_upload(body.targets_upload_id)
            if not targets_upload or targets_upload.get("kind") != "targets":
                raise HTTPException(status_code=404, detail="target upload not found")
            if not Path(targets_upload.get("stored_path") or "").is_file():
                raise HTTPException(status_code=410, detail="target upload no longer exists")
        target_count = len(targets) + int((targets_upload or {}).get("item_count") or 0)
        if not target_count:
            raise HTTPException(status_code=400, detail="no targets provided")
        custom_paths = list(dict.fromkeys(body.custom_paths))
        wordlist_upload: Optional[dict[str, Any]] = None
        if body.wordlist_upload_id:
            wordlist_upload = store.get_upload(body.wordlist_upload_id)
            if not wordlist_upload or wordlist_upload.get("kind") != "wordlist":
                raise HTTPException(status_code=404, detail="wordlist upload not found")
        cfg = ScanConfig(
            targets=targets,
            target_count=target_count,
            job_name=body.job_name.strip()[:120],
            targets_upload_id=body.targets_upload_id,
            wordlist_upload_id=body.wordlist_upload_id,
            threads=max(1, min(int(body.threads or 20), 500)),
            # Each process runs its own GIL and its own full Threads budget
            # (threads is per-process). Cap process count by CPU so one job
            # cannot spawn more workers than the box can usefully run.
            worker_processes=max(1, min(int(body.worker_processes or 1), os.cpu_count() or 4, 16)),
            timeout=body.timeout,
            # Dead/filtered hosts dominate large recon lists; failing to
            # connect quickly (rather than waiting the full read timeout)
            # is a bigger speed lever than raw thread count. Defaults to
            # min(timeout, 5s) unless the caller sets it explicitly.
            connect_timeout=body.connect_timeout or min(body.timeout or 8.0, 5.0),
            retries=body.retries,
            rate_limit_per_host=max(1.0, float(body.rate_limit_per_host or 50.0)),
            modules=body.modules,
            paths_mode=body.paths_mode,
            custom_paths=custom_paths,
            custom_path_count=len(custom_paths) + int((wordlist_upload or {}).get("item_count") or 0),
            scope_notes=body.scope_notes,
            redact_secrets=False,
            verify_tls=body.verify_tls,
            method_test_trace=body.method_test_trace,
            verbose=body.verbose,
            exploit_enabled=bool(body.exploit_enabled),
            exploit_command=(body.exploit_command or "id").strip()[:200] or "id",
            exploit_all=bool(body.exploit_all),
            output_dir=str(ROOT / "output" / "scans"),
        )
        ssh_server_ids = [sid for sid in (body.ssh_server_ids or []) if isinstance(sid, str) and sid.strip()]
        ssh_preflight: list[dict[str, Any]] = []
        if ssh_server_ids:
            ssh_preflight = await asyncio.to_thread(preflight_servers, ssh_store, ssh_server_ids)
            failed = [row for row in ssh_preflight if not row.get("ok")]
            if failed:
                names = ", ".join(
                    (row.get("label") or row.get("host") or row.get("id") or "?") for row in failed
                )
                detail = failed[0].get("error") or "SSH preflight failed"
                raise HTTPException(
                    status_code=400,
                    detail=f"Selected SSH server(s) not ready: {names}. {detail}",
                )
        out_dir = Path(cfg.output_dir) / cfg.scan_id
        out_dir.mkdir(parents=True, exist_ok=True)
        # Hard-link large uploads into the scan directory in O(1). The job no
        # longer waits for a 500MB parse/copy, and deleting the library item
        # cannot remove the scan's source file.
        if targets_upload:
            source = Path(targets_upload["stored_path"])
            snapshot = out_dir / "targets.txt"
            try:
                snapshot.hardlink_to(source)
                cfg.targets_path = str(snapshot)
            except OSError:
                cfg.targets_path = str(source)
        if wordlist_upload:
            source = Path(wordlist_upload["stored_path"])
            snapshot = out_dir / "custom_paths.txt"
            try:
                snapshot.hardlink_to(source)
                cfg.wordlist_path = str(snapshot)
            except OSError:
                cfg.wordlist_path = str(source)
        # Register the job immediately with a slim config so the Jobs tab can
        # refresh even if the worker thread is still starting.
        store.create_scan(
            cfg.scan_id,
            {
                "job_name": cfg.job_name,
                "targets_upload_id": cfg.targets_upload_id,
                "wordlist_upload_id": cfg.wordlist_upload_id,
                "threads": cfg.threads,
                "worker_processes": cfg.worker_processes,
                "timeout": cfg.timeout,
                "connect_timeout": cfg.connect_timeout,
                "retries": cfg.retries,
                "rate_limit_per_host": cfg.rate_limit_per_host,
                "modules": cfg.modules,
                "paths_mode": cfg.paths_mode,
                "scope_notes": cfg.scope_notes,
                "redact_secrets": cfg.redact_secrets,
                "verify_tls": cfg.verify_tls,
                "method_test_trace": cfg.method_test_trace,
                "verbose": cfg.verbose,
                "exploit_enabled": cfg.exploit_enabled,
                "exploit_command": cfg.exploit_command,
                "exploit_all": cfg.exploit_all,
                "output_dir": cfg.output_dir,
                "scan_id": cfg.scan_id,
                "target_count": cfg.target_count,
                "custom_path_count": cfg.custom_path_count,
                "ssh_server_ids": ssh_server_ids,
                "ssh_servers": [
                    {
                        "id": row.get("id"),
                        "host": row.get("host"),
                        "endpoint": row.get("endpoint"),
                        "label": row.get("label"),
                        "auth_type": row.get("auth_type"),
                        "hostname": row.get("hostname"),
                        "ok": row.get("ok"),
                    }
                    for row in ssh_preflight
                ],
            },
            str(out_dir),
        )
        store.update_status(cfg.scan_id, "pending")
        engine.start_async(cfg)
        return {
            "id": cfg.scan_id,
            "status": "running",
            "ssh_server_ids": ssh_server_ids,
            "ssh_preflight": ssh_preflight,
        }

    @app.get("/api/scans")
    async def list_scans(
        limit: int = 100,
        compact: bool = False,
        include_archived: bool = False,
    ) -> list[dict[str, Any]]:
        return store.list_scans(
            limit=limit,
            compact=compact,
            include_archived=include_archived,
        )

    @app.get("/api/scans/{scan_id}")
    async def get_scan(scan_id: str) -> dict[str, Any]:
        row = store.get_scan(scan_id)
        return row or {"error": "not found"}

    @app.post("/api/scans/{scan_id}/resume")
    async def resume_scan(scan_id: str) -> dict[str, Any]:
        return await asyncio.to_thread(_resume_scan, scan_id)

    @app.get("/api/servers")
    async def list_servers() -> list[dict[str, Any]]:
        return [public_server_dict(s) for s in ssh_store.list()]

    @app.post("/api/servers")
    async def create_server(body: SshServerCreate) -> dict[str, Any]:
        host = (body.host or "").strip()
        if not host:
            raise HTTPException(status_code=400, detail="host is required")
        auth_type = "password" if (body.auth_type or "").lower() == "password" else "key"
        private_key = (body.private_key or "").strip()
        password = body.password or ""
        if auth_type == "key" and not private_key:
            raise HTTPException(status_code=400, detail="private_key is required for key auth")
        if auth_type == "password" and not password:
            raise HTTPException(status_code=400, detail="password is required for password auth")
        connect_ip = (body.connect_ip or "").strip()
        # If host is already an IP, also use it as the connect target.
        if not connect_ip:
            try:
                import ipaddress

                ipaddress.ip_address(host)
                connect_ip = host
            except ValueError:
                connect_ip = ""
        server = SshServer(
            id=new_server_id(),
            host=host,
            port=max(1, min(int(body.port or 22), 65535)),
            username=(body.username or "ubuntu").strip() or "ubuntu",
            auth_type=auth_type,
            private_key=private_key if auth_type == "key" else "",
            password=password if auth_type == "password" else "",
            label=(body.label or "").strip()[:120],
            connect_ip=connect_ip,
            status="unknown",
        )
        # Auto-detect private Connect IP when operator didn't provide one.
        if not server.connect_ip:
            from app.core.ssh_servers import auto_detect_connect_ip

            detected = await asyncio.to_thread(auto_detect_connect_ip, server, deep=False)
            if detected.get("ok") and detected.get("connect_ip"):
                server.connect_ip = str(detected["connect_ip"])
        # Probe once on create so the card shows Online/Offline immediately.
        metrics = await asyncio.to_thread(collect_metrics, server)
        server.metrics = metrics
        server.status = "online" if metrics.get("online") else "offline"
        server.last_error = str(metrics.get("error") or "")
        ssh_store.upsert(server)
        return public_server_dict(server)

    @app.get("/api/servers/{server_id}")
    async def get_server(server_id: str) -> dict[str, Any]:
        server = ssh_store.get(server_id)
        if not server:
            raise HTTPException(status_code=404, detail="server not found")
        return public_server_dict(server)

    @app.delete("/api/servers/{server_id}")
    async def delete_server(server_id: str) -> dict[str, Any]:
        if not ssh_store.delete(server_id):
            raise HTTPException(status_code=404, detail="server not found")
        return {"deleted": True, "id": server_id}

    @app.post("/api/servers/{server_id}/metrics")
    async def refresh_server_metrics(server_id: str) -> dict[str, Any]:
        server = ssh_store.get(server_id)
        if not server:
            raise HTTPException(status_code=404, detail="server not found")
        metrics = await asyncio.to_thread(collect_metrics, server)
        server.metrics = metrics
        server.status = "online" if metrics.get("online") else "offline"
        server.last_error = str(metrics.get("error") or "")
        ssh_store.upsert(server)
        return public_server_dict(server)

    @app.post("/api/servers/refresh")
    async def refresh_all_server_metrics() -> list[dict[str, Any]]:
        servers = ssh_store.list()

        def _refresh_one(server: SshServer) -> SshServer:
            metrics = collect_metrics(server)
            server.metrics = metrics
            server.status = "online" if metrics.get("online") else "offline"
            server.last_error = str(metrics.get("error") or "")
            return ssh_store.upsert(server)

        refreshed = await asyncio.gather(*[
            asyncio.to_thread(_refresh_one, server) for server in servers
        ])
        return [public_server_dict(s) for s in refreshed]

    @app.post("/api/servers/{server_id}/install-deps")
    async def install_server_deps(server_id: str) -> dict[str, Any]:
        server = ssh_store.get(server_id)
        if not server:
            raise HTTPException(status_code=404, detail="server not found")
        result = await asyncio.to_thread(install_deps, server)
        # Refresh metrics after install so Online/Offline stays current.
        metrics = await asyncio.to_thread(collect_metrics, server)
        server.metrics = metrics
        server.status = "online" if metrics.get("online") else "offline"
        server.last_error = str(metrics.get("error") or "") if not result.get("ok") else ""
        server.last_install = {
            "ok": bool(result.get("ok")),
            "message": str(result.get("message") or ""),
            "exit_code": result.get("exit_code"),
            "at": result.get("at") or "",
        }
        ssh_store.upsert(server)
        return {"server": public_server_dict(server), **result}

    class SshServerConnectIpUpdate(BaseModel):
        connect_ip: str = ""

    @app.patch("/api/servers/{server_id}")
    async def patch_server(server_id: str, body: SshServerConnectIpUpdate) -> dict[str, Any]:
        """Update connect IP (private IP) and re-probe without recreating the server."""
        server = ssh_store.get(server_id)
        if not server:
            raise HTTPException(status_code=404, detail="server not found")
        connect_ip = (body.connect_ip or "").strip()
        if connect_ip:
            try:
                import ipaddress

                ipaddress.ip_address(connect_ip)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="connect_ip must be a valid IP") from exc
        server.connect_ip = connect_ip
        metrics = await asyncio.to_thread(collect_metrics, server)
        server.metrics = metrics
        server.status = "online" if metrics.get("online") else "offline"
        server.last_error = str(metrics.get("error") or "")
        ssh_store.upsert(server)
        return public_server_dict(server)

    @app.post("/api/servers/{server_id}/detect-ip")
    async def detect_server_ip(server_id: str) -> dict[str, Any]:
        """Auto-detect private Connect IP (DNS / SSH metadata / VPC key probe)."""
        from app.core.ssh_servers import auto_detect_connect_ip

        server = ssh_store.get(server_id)
        if not server:
            raise HTTPException(status_code=404, detail="server not found")
        detected = await asyncio.to_thread(auto_detect_connect_ip, server, deep=True)
        if detected.get("ok") and detected.get("connect_ip"):
            server.connect_ip = str(detected["connect_ip"])
        metrics = await asyncio.to_thread(collect_metrics, server)
        server.metrics = metrics
        server.status = "online" if metrics.get("online") else "offline"
        server.last_error = "" if detected.get("ok") else str(detected.get("message") or metrics.get("error") or "")
        ssh_store.upsert(server)
        return {"server": public_server_dict(server), **detected}

    @app.get("/api/scans/{scan_id}/findings")
    async def get_findings(
        scan_id: str,
        severity: Optional[str] = None,
        type: Optional[str] = None,
        module: Optional[str] = None,
        q: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        if not store.get_scan(scan_id, compact=True):
            raise HTTPException(status_code=404, detail="scan not found")
        size = max(1, min(int(page_size or 20), 100))
        page_n = max(1, int(page or 1))
        items, total = store.query_findings(
            scan_id,
            severity=severity,
            ftype=type,
            module=module,
            q=q,
            limit=size,
            offset=(page_n - 1) * size,
        )
        return {
            "items": items,
            "total": total,
            "page": page_n,
            "page_size": size,
            "pages": max(1, (total + size - 1) // size) if total else 1,
        }

    @app.get("/api/scans/{scan_id}/findings/{finding_id}")
    async def get_finding(scan_id: str, finding_id: str) -> dict[str, Any]:
        finding = store.get_finding(scan_id, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="finding not found")
        return finding

    @app.get("/api/scans/{scan_id}/logs")
    async def get_logs(
        scan_id: str,
        level: Optional[str] = None,
        module: Optional[str] = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        rows = store.get_logs(scan_id, level=level, module=module, limit=limit)
        if rows:
            return rows
        scan = store.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="scan not found")
        return read_file_logs(
            scan.get("output_dir") or (ROOT / "output" / "scans" / scan_id),
            level=level,
            module=module,
            limit=limit,
        )

    @app.post("/api/scans/{scan_id}/stop")
    async def stop_scan(scan_id: str) -> dict[str, Any]:
        ok = engine.stop(scan_id)
        if not store.get_scan(scan_id):
            raise HTTPException(status_code=404, detail="scan not found")
        return {"stopped": ok, "id": scan_id, "status": store.get_scan(scan_id).get("status")}

    @app.delete("/api/scans/{scan_id}")
    async def delete_scan(scan_id: str) -> dict[str, Any]:
        row = store.get_scan(scan_id)
        if not row:
            raise HTTPException(status_code=404, detail="scan not found")
        if engine.is_active(scan_id) or row.get("status") in {"pending", "running", "stopping"}:
            raise HTTPException(status_code=409, detail="stop the running job before deleting it")

        # "Delete" removes the operational job card only. Findings, logs,
        # reports, and artifacts remain queryable from Results.
        store.archive_scan(scan_id)
        return {"deleted": True, "archived": True, "results_preserved": True, "id": scan_id}

    @app.delete("/api/scans/{scan_id}/purge")
    async def purge_scan(scan_id: str) -> dict[str, Any]:
        row = store.get_scan(scan_id)
        if not row:
            raise HTTPException(status_code=404, detail="scan not found")
        if engine.is_active(scan_id) or row.get("status") in {"pending", "running", "stopping"}:
            raise HTTPException(status_code=409, detail="stop the running job before deleting its results")
        out_dir = Path(row.get("output_dir") or "").resolve()
        scans_root = (ROOT / "output" / "scans").resolve()
        if out_dir.parent == scans_root and out_dir.name == scan_id and out_dir.is_dir():
            await asyncio.to_thread(shutil.rmtree, out_dir, True)
        store.delete_scan(scan_id)
        return {"deleted": True, "purged": True, "id": scan_id}

    async def _save_upload(file: UploadFile, kind: str) -> dict[str, Any]:
        if file.size is not None and file.size > DIRECT_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail="files over 32 MB must use the chunked upload API",
            )
        content = await file.read(DIRECT_UPLOAD_BYTES + 1)
        if len(content) > DIRECT_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail="files over 32 MB must use the chunked upload API",
            )
        try:
            return create_upload(
                store,
                UPLOAD_DIR,
                kind=kind,  # type: ignore[arg-type]
                filename=file.filename or f"{kind}.txt",
                content=content,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/uploads")
    async def upload_file(
        file: UploadFile = File(...),
        kind: str = Form("targets"),
    ) -> dict[str, Any]:
        return await _save_upload(file, kind)

    @app.post("/api/uploads/chunks/init")
    async def init_upload(body: ChunkUploadInit) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                init_chunk_upload,
                UPLOAD_DIR,
                kind=body.kind,
                filename=body.filename,
                total_size=body.total_size,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/uploads/chunks/{upload_id}")
    async def chunk_upload_status(upload_id: str) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(get_chunk_upload_status, UPLOAD_DIR, upload_id)
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.put("/api/uploads/chunks/{upload_id}/{chunk_index}")
    async def upload_chunk(upload_id: str, chunk_index: int, request: Request) -> dict[str, Any]:
        # Browser chunks are 8 MiB, keeping request memory bounded even for 5GB files.
        content = await request.body()
        try:
            return await asyncio.to_thread(
                write_upload_chunk,
                UPLOAD_DIR,
                upload_id,
                chunk_index,
                content,
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/uploads/chunks/{upload_id}/complete")
    async def complete_upload(upload_id: str) -> dict[str, Any]:
        try:
            return await asyncio.to_thread(
                complete_chunk_upload,
                store,
                UPLOAD_DIR,
                upload_id,
            )
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/uploads")
    async def list_uploads(kind: Optional[str] = None) -> list[dict[str, Any]]:
        if kind and kind not in {"targets", "wordlist"}:
            raise HTTPException(status_code=400, detail="invalid upload kind")
        rows = store.list_uploads(kind=kind)
        for row in rows:
            row["exists"] = Path(row.get("stored_path") or "").is_file()
        return rows

    @app.get("/api/uploads/{upload_id}")
    async def get_upload(upload_id: str) -> dict[str, Any]:
        row = store.get_upload(upload_id)
        if not row:
            raise HTTPException(status_code=404, detail="upload not found")
        try:
            items = await asyncio.to_thread(preview_upload_items, row, 50)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=410, detail=str(exc)) from exc
        return {**row, "preview": items, "exists": True}

    @app.get("/api/uploads/{upload_id}/download")
    async def download_upload(upload_id: str) -> FileResponse:
        row = store.get_upload(upload_id)
        if not row:
            raise HTTPException(status_code=404, detail="upload not found")
        try:
            path = safe_download_path(row, UPLOAD_DIR)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=410, detail=str(exc)) from exc
        return FileResponse(
            path,
            filename=row.get("original_name") or path.name,
            media_type="application/octet-stream",
        )

    @app.delete("/api/uploads/{upload_id}")
    async def delete_upload(upload_id: str) -> dict[str, Any]:
        row = store.get_upload(upload_id)
        if not row:
            raise HTTPException(status_code=404, detail="upload not found")
        delete_upload_file(row, UPLOAD_DIR)
        store.delete_upload(upload_id)
        return {"deleted": True, "id": upload_id}

    # Backward-compatible upload routes used by older clients.
    @app.post("/api/wordlists/upload")
    async def upload_wordlist(
        file: UploadFile = File(...),
        mode: str = Form("merge"),
    ) -> dict[str, Any]:
        record = await _save_upload(file, "wordlist")
        return {**record, "mode": mode, "paths_preview": record["preview"]}

    @app.post("/api/targets/upload")
    async def upload_targets(file: UploadFile = File(...)) -> dict[str, Any]:
        record = await _save_upload(file, "targets")
        targets = read_upload_items(record)
        return {
            **record,
            "path": record["stored_path"],
            "count": record["item_count"],
            "targets": targets,
            "targets_text": "\n".join(targets),
        }

    def _raw_secrets_from_finding(f: dict[str, Any]) -> list[dict[str, Any]]:
        raw_secrets: list[dict[str, Any]] = []
        extracted = f.get("extracted") or {}
        source_url = f.get("url") or ""
        mod = f.get("module") or "unknown"
        found_at = str(f.get("timestamp") or "")
        base_meta = {
            "module": mod,
            "modules": [mod] if mod else [],
            "timestamp": found_at,
            "title": f.get("title") or "",
            "finding_id": f.get("id") or "",
        }
        for secret in extracted.get("secrets") or []:
            raw_secrets.append(
                {
                    "kind": secret.get("kind") or "secret",
                    "value": secret.get("value"),
                    "source_url": secret.get("source_url") or source_url,
                    "sources": [secret.get("source_url") or source_url],
                    "occurrences": 1,
                    **base_meta,
                }
            )
        for smtp_item in extracted.get("smtp") or []:
            raw_secrets.append(
                {
                    "kind": smtp_item.get("kind") or "smtp",
                    "value": smtp_item.get("value"),
                    "source_url": smtp_item.get("source_url") or source_url,
                    "sources": [smtp_item.get("source_url") or source_url],
                    "occurrences": 1,
                    **base_meta,
                }
            )
        if not (extracted.get("secrets") or extracted.get("smtp")):
            # Legacy active-exploit findings stored dump lines in evidence
            # only. Keep credential-looking lines; skip bash timestamps.
            from app.modules.base import _looks_like_credential_line

            ftype = str(f.get("type") or "")
            if ftype == "secrets" and f.get("evidence"):
                for line in str(f.get("evidence") or "").splitlines():
                    if not _looks_like_credential_line(line):
                        continue
                    raw_secrets.append(
                        {
                            "kind": "exploit",
                            "value": line.strip(),
                            "source_url": source_url,
                            "sources": [source_url] if source_url else [],
                            "occurrences": 1,
                            **base_meta,
                        }
                    )
        return raw_secrets

    def _host_map_from_findings(findings: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        host_map: dict[str, dict[str, Any]] = {}
        for f in findings:
            if not is_vuln_worthy(f):
                continue
            sev = f.get("severity") or "info"
            mod = f.get("module") or "unknown"
            cats = classify_finding(f)
            host = host_from_finding(f)
            method = detection_method(f, cats)
            bucket = host_map.setdefault(
                host,
                {
                    "host": host,
                    "methods": set(),
                    "modules": set(),
                    "severities": set(),
                    "finding_count": 0,
                    "findings": [],
                },
            )
            bucket["methods"].add(method)
            bucket["modules"].add(mod)
            bucket["severities"].add(sev)
            bucket["finding_count"] += 1
            bucket["findings"].append(
                {
                    "method": method,
                    "module": mod,
                    "severity": sev,
                    "title": f.get("title"),
                    "url": f.get("url"),
                    "categories": cats,
                    "confidence": f.get("confidence"),
                    "id": f.get("id"),
                }
            )
        return host_map

    def _host_map_from_vuln_indexes(out_dir: Path) -> Optional[dict[str, dict[str, Any]]]:
        """Build host map from on-disk vulns indexes when present (thousands of rows)."""
        vulns_dir = out_dir / "vulns"
        if not vulns_dir.is_dir():
            return None
        index_paths = sorted(vulns_dir.rglob("index.jsonl"))
        if not index_paths:
            return None
        host_map: dict[str, dict[str, Any]] = {}
        saw_row = False
        for path in index_paths:
            try:
                with path.open("r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            f = json.loads(line)
                        except Exception:
                            continue
                        if not isinstance(f, dict):
                            continue
                        saw_row = True
                        sev = f.get("severity") or "info"
                        mod = f.get("module") or "unknown"
                        cats = f.get("categories") or classify_finding(f)
                        if not isinstance(cats, list):
                            cats = classify_finding(f)
                        host = f.get("host") or host_from_finding(f)
                        method = f.get("method") or detection_method(f, cats)
                        bucket = host_map.setdefault(
                            host,
                            {
                                "host": host,
                                "methods": set(),
                                "modules": set(),
                                "severities": set(),
                                "finding_count": 0,
                                "findings": [],
                            },
                        )
                        bucket["methods"].add(method)
                        bucket["modules"].add(mod)
                        bucket["severities"].add(sev)
                        bucket["finding_count"] += 1
                        bucket["findings"].append(
                            {
                                "method": method,
                                "module": mod,
                                "severity": sev,
                                "title": f.get("title"),
                                "url": f.get("url"),
                                "categories": cats,
                                "confidence": f.get("confidence"),
                                "id": f.get("id"),
                            }
                        )
            except OSError:
                continue
        return host_map if saw_row else None

    def _build_results_payload(
        scan_id: str,
        *,
        provider: Optional[str] = None,
        include_findings: bool = False,
        hosts_page: int = 1,
        hosts_page_size: int = 20,
    ) -> dict[str, Any]:
        """Results aggregation — must not run on the asyncio event loop.

        Avoids loading every finding row. Million-row scans previously spent
        60–90s+ materializing SQLite into Python just to show a 60KB summary.
        """
        row = store.get_scan(scan_id, compact=True)
        if not row:
            raise KeyError("scan not found")

        stats = store.finding_stats(scan_id)
        by_severity = stats["by_severity"]
        by_module = stats["by_module"]
        finding_count = int(stats["finding_count"])

        secret_findings = dedupe_findings(store.get_secret_candidate_findings(scan_id))
        raw_secrets: list[dict[str, Any]] = []
        for f in secret_findings:
            raw_secrets.extend(_raw_secrets_from_finding(f))

        secrets = normalize_result_secrets(raw_secrets)
        # Provider counts must reflect the post-normalized secret list
        # (paired AWS rows collapse two kinds into one).
        provider_counts: dict[str, int] = {}
        cleaned: list[dict[str, Any]] = []
        for item in secrets:
            kind = str(item.get("kind") or "")
            value = item.get("value")
            if not isinstance(value, str):
                value = _format_credential_value(kind, value)
            value = str(value or "").replace("\r", "").strip()
            if not value or _is_useless_secret(kind, value):
                continue
            provider_id = item.get("provider") or provider_for_kind(kind)
            item = {**item, "kind": kind, "value": value, "provider": provider_id}
            cleaned.append(item)
            provider_counts[provider_id] = provider_counts.get(provider_id, 0) + 1
        secrets = cleaned
        if provider:
            secrets = [item for item in secrets if item.get("provider") == provider]

        out_dir = Path(row.get("output_dir") or (ROOT / "output" / "scans" / scan_id))
        host_map = _host_map_from_vuln_indexes(out_dir)
        if host_map is None:
            # Small jobs / missing artifacts: scan vuln-candidate rows only.
            host_map = _host_map_from_findings(
                dedupe_findings(store.get_vuln_candidate_findings(scan_id))
            )

        vulnerable_hosts = []
        for host, bucket in sorted(host_map.items()):
            vulnerable_hosts.append(
                {
                    "host": host,
                    "methods": sorted(bucket["methods"]),
                    "modules": sorted(bucket["modules"]),
                    "severities": sorted(bucket["severities"]),
                    "finding_count": bucket["finding_count"],
                    # Keep the job-switch payload small. Full finding details
                    # are available on demand from /findings/{finding_id}.
                    "recent_findings": bucket["findings"][:5],
                }
            )

        host_size = max(1, min(int(hosts_page_size or 20), 100))
        host_page = max(1, int(hosts_page or 1))
        host_total = len(vulnerable_hosts)
        host_start = (host_page - 1) * host_size
        hosts_page_items = vulnerable_hosts[host_start : host_start + host_size]

        # Report the on-disk vulns/ tree if one already exists, without
        # rewriting it here. This endpoint is polled on every filter click,
        # and regenerating dozens of per-category files on each read made
        # filtering feel slow; artifact generation belongs to the live
        # scan persistence path and the explicit /vulns endpoint instead.
        vuln_files: dict[str, Any] = {}
        summary_path = out_dir / "vulns" / "summary.json"
        if summary_path.is_file():
            try:
                vuln_files = {
                    "dir": str(out_dir / "vulns"),
                    "summary": json.loads(summary_path.read_text(encoding="utf-8")),
                }
            except Exception:
                vuln_files = {}

        payload = {
            "scan": row,
            "finding_count": finding_count,
            "by_severity": by_severity,
            "by_module": by_module,
            "secrets": secrets,
            "providers": [
                provider_metadata(provider_id, count)
                for provider_id, count in sorted(provider_counts.items())
            ],
            "vulnerable_hosts": hosts_page_items,
            "vulnerable_host_count": host_total,
            "hosts_page": host_page,
            "hosts_page_size": host_size,
            "hosts_pages": max(1, (host_total + host_size - 1) // host_size) if host_total else 1,
            "vuln_files": vuln_files,
        }
        # Findings are loaded via paginated /findings. Including them here
        # duplicated large payloads on every Results poll.
        if include_findings:
            page_items, _ = store.query_findings(scan_id, limit=100, offset=0)
            payload["findings"] = [
                {
                    "id": finding.get("id"),
                    "type": finding.get("type"),
                    "severity": finding.get("severity"),
                    "module": finding.get("module"),
                    "title": finding.get("title"),
                    "url": finding.get("url"),
                    "timestamp": finding.get("timestamp"),
                    "validated": finding.get("validated"),
                }
                for finding in page_items
            ]
        return payload

    def _schedule_results_refresh(
        cache_key: str,
        scan_id: str,
        *,
        provider: Optional[str],
        include_findings: bool,
        hosts_page: int,
        hosts_page_size: int,
    ) -> None:
        with _RESULTS_CACHE_LOCK:
            if cache_key in _RESULTS_REFRESHING:
                return
            _RESULTS_REFRESHING.add(cache_key)

        def _worker() -> None:
            try:
                payload = _build_results_payload(
                    scan_id,
                    provider=provider,
                    include_findings=include_findings,
                    hosts_page=hosts_page,
                    hosts_page_size=hosts_page_size,
                )
                _results_cache_set(cache_key, payload)
            except Exception:
                log.exception("background results refresh failed for %s", scan_id)
            finally:
                with _RESULTS_CACHE_LOCK:
                    _RESULTS_REFRESHING.discard(cache_key)

        threading.Thread(target=_worker, name=f"results-refresh-{scan_id[:8]}", daemon=True).start()

    @app.get("/api/scans/{scan_id}/results")
    async def get_results(
        scan_id: str,
        provider: Optional[str] = None,
        include_findings: bool = False,
        hosts_page: int = 1,
        hosts_page_size: int = 20,
    ) -> dict[str, Any]:
        cache_key = (
            f"{scan_id}|{provider or ''}|{int(include_findings)}|"
            f"{int(hosts_page or 1)}|{int(hosts_page_size or 20)}"
        )
        cached, stale = _results_cache_get(cache_key, allow_stale=True)
        if cached is not None and not stale:
            return cached
        if cached is not None and stale:
            _schedule_results_refresh(
                cache_key,
                scan_id,
                provider=provider,
                include_findings=include_findings,
                hosts_page=hosts_page,
                hosts_page_size=hosts_page_size,
            )
            return cached
        try:
            payload = await asyncio.to_thread(
                _build_results_payload,
                scan_id,
                provider=provider,
                include_findings=include_findings,
                hosts_page=hosts_page,
                hosts_page_size=hosts_page_size,
            )
        except KeyError:
            raise HTTPException(status_code=404, detail="scan not found") from None
        _results_cache_set(cache_key, payload)
        return payload

    @app.get("/api/scans/{scan_id}/vulns")
    async def list_vuln_files(scan_id: str) -> dict[str, Any]:
        row = store.get_scan(scan_id)
        if not row:
            raise HTTPException(status_code=404, detail="scan not found")
        base = Path(row.get("output_dir") or (ROOT / "output" / "scans" / scan_id)) / "vulns"
        if not base.exists():
            findings = store.get_findings(scan_id)
            write_vuln_artifacts(base.parent, findings)
        files = []
        if base.exists():
            for path in sorted(base.rglob("*")):
                if path.is_file():
                    files.append(str(path.relative_to(base)))
        return {"scan_id": scan_id, "dir": str(base), "files": files}

    @app.get("/api/scans/{scan_id}/export/{fmt}")
    async def export_report(scan_id: str, fmt: str) -> FileResponse:
        base = ROOT / "output" / "scans" / scan_id
        mapping = {
            "json": base / "report.json",
            "md": base / "report.md",
            "csv": base / "findings.csv",
            "vulns_csv": base / "vulns" / "by_target.csv",
            "vulns_md": base / "vulns" / "by_target.md",
            "vulns_json": base / "vulns" / "by_target.json",
            "hosts": base / "vulns" / "hosts.txt",
        }
        path = mapping.get(fmt)
        if not path or not path.exists():
            raise HTTPException(status_code=404, detail=f"missing export {fmt}")
        return FileResponse(path)

    @app.websocket("/ws/scans/{scan_id}")
    async def ws_scan(ws: WebSocket, scan_id: str) -> None:
        await manager.connect(ws)
        try:
            # send current snapshot
            row = store.get_scan(scan_id)
            if row:
                await ws.send_text(json.dumps({"type": "scan", "scan_id": scan_id, "data": row}))
            while True:
                # keep alive / allow client pings
                msg = await ws.receive_text()
                if msg == "ping":
                    await ws.send_text(json.dumps({"type": "pong"}))
        except WebSocketDisconnect:
            manager.disconnect(ws)
        except Exception:
            manager.disconnect(ws)

    return app


app = create_app()