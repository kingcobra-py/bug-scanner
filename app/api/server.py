"""FastAPI dashboard API + static UI."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import threading
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.core.engine import ScanEngine
from app.core.providers import provider_for_kind, provider_metadata
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

store = ScanStore(ROOT / "output" / "scans" / "scanner.db")
engine = ScanEngine(store=store, enable_cli_progress=False)
LOG_LINE = re.compile(
    r"^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<level>[A-Z]+)\]\s+\[(?P<module>[^\]]+)\]\s*(?P<message>.*)$"
)


def normalize_result_secrets(secrets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prefer ``AKIA...:secret`` pairs and drop duplicate standalone access keys.

    Legacy extractors stored pairs as ``access|secret``; normalize those to
    colon form for the Results UI. When both a paired cred and a bare
    ``aws_access_key`` exist for the same access key, keep only the pair.
    """
    normalized: list[dict[str, Any]] = []
    paired_access: set[str] = set()
    for item in secrets:
        kind = str(item.get("kind") or "")
        value = str(item.get("value") or "")
        if "|" in value and (kind.startswith("aws") or value.startswith("AKIA")):
            left, right = value.split("|", 1)
            if left.startswith("AKIA") and right:
                value = f"{left}:{right}"
                kind = "aws_cred"
                item = {**item, "kind": kind, "value": value}
        if kind == "aws_cred" and ":" in value:
            paired_access.add(value.split(":", 1)[0])
        normalized.append(item)

    out: list[dict[str, Any]] = []
    for item in normalized:
        if item.get("kind") == "aws_access_key" and item.get("value") in paired_access:
            continue
        out.append(item)
    return out


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


class ChunkUploadInit(BaseModel):
    filename: str
    kind: str = "targets"
    total_size: int


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
        # Worker threads do not survive a service restart. Reconcile stale
        # persisted rows so they can be deleted and never look unstoppable.
        for scan in store.list_scans(limit=1000, compact=True):
            if scan.get("status") in {"pending", "running", "stopping"} and not engine.is_active(scan["id"]):
                store.update_status(scan["id"], "stopped")
        # One-time shrink of legacy summary_json rows that still embed the full
        # target list (those alone made /api/scans compact responses >1MB).
        try:
            store.slim_stored_summaries()
        except Exception:
            pass

    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        html = (UI_DIR / "templates" / "index.html").read_text(encoding="utf-8")
        return HTMLResponse(html)

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
            output_dir=str(ROOT / "output" / "scans"),
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
                "output_dir": cfg.output_dir,
                "scan_id": cfg.scan_id,
                "target_count": cfg.target_count,
                "custom_path_count": cfg.custom_path_count,
            },
            str(out_dir),
        )
        store.update_status(cfg.scan_id, "pending")
        engine.start_async(cfg)
        return {"id": cfg.scan_id, "status": "running"}

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

    @app.get("/api/scans/{scan_id}/results")
    async def get_results(
        scan_id: str,
        provider: Optional[str] = None,
        include_findings: bool = False,
        hosts_page: int = 1,
        hosts_page_size: int = 20,
    ) -> dict[str, Any]:
        row = store.get_scan(scan_id, compact=True)
        if not row:
            raise HTTPException(status_code=404, detail="scan not found")
        findings = dedupe_findings(store.get_findings(scan_id))
        by_severity: dict[str, int] = {}
        by_module: dict[str, int] = {}
        secrets: list[dict[str, Any]] = []
        secret_index: dict[str, dict[str, Any]] = {}
        provider_counts: dict[str, int] = {}
        host_map: dict[str, dict[str, Any]] = {}
        for f in findings:
            sev = f.get("severity") or "info"
            mod = f.get("module") or "unknown"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_module[mod] = by_module.get(mod, 0) + 1
            extracted = f.get("extracted") or {}
            for secret in extracted.get("secrets") or []:
                kind = secret.get("kind") or "secret"
                provider_id = provider_for_kind(kind)
                source_url = secret.get("source_url") or f.get("url")
                key = f"{provider_id}:{kind}:{value_hash(str(secret.get('value') or ''))}"
                if key not in secret_index:
                    secret_index[key] = {
                        "kind": kind,
                        "provider": provider_id,
                        "value": secret.get("value"),
                        "source_url": source_url,
                        "sources": [source_url] if source_url else [],
                        "occurrences": 1,
                        "module": mod,
                        "title": f.get("title"),
                        "finding_id": f.get("id"),
                    }
                    provider_counts[provider_id] = provider_counts.get(provider_id, 0) + 1
                else:
                    item = secret_index[key]
                    item["occurrences"] += 1
                    if source_url and source_url not in item["sources"]:
                        item["sources"].append(source_url)
            if not is_vuln_worthy(f):
                continue
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

        secrets = normalize_result_secrets(list(secret_index.values()))
        # Provider counts must reflect the post-normalized secret list
        # (paired AWS rows collapse two kinds into one).
        provider_counts = {}
        for item in secrets:
            provider_id = item.get("provider") or provider_for_kind(str(item.get("kind") or ""))
            item["provider"] = provider_id
            provider_counts[provider_id] = provider_counts.get(provider_id, 0) + 1
        if provider:
            secrets = [item for item in secrets if item.get("provider") == provider]

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
        out_dir = Path(row.get("output_dir") or (ROOT / "output" / "scans" / scan_id))
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
            "finding_count": len(findings),
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
                for finding in findings[:100]
            ]
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