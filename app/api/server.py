"""FastAPI dashboard API + static UI."""

from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app.core.engine import ScanEngine
from app.core.providers import provider_for_kind, provider_metadata
from app.core.uploads import create_upload, delete_upload_file, read_upload_items
from app.core.vuln_artifacts import classify_finding, detection_method, host_from_finding, is_vuln_worthy, write_vuln_artifacts
from app.storage.db import ScanStore
from app.storage.models import ScanConfig
from app.utils.dedupe import dedupe_findings, value_hash

ROOT = Path(__file__).resolve().parents[2]
UI_DIR = ROOT / "app" / "ui"
UPLOAD_DIR = ROOT / "output" / "uploads"

store = ScanStore(ROOT / "output" / "scans" / "scanner.db")
engine = ScanEngine(store=store, enable_cli_progress=False)


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
    timeout: float = 8.0
    retries: int = 2
    rate_limit_per_host: float = 50.0
    paths_mode: str = "merge"
    custom_paths: list[str] = Field(default_factory=list)
    scope_notes: str = ""
    verify_tls: bool = False
    redact_secrets: bool = True
    method_test_trace: bool = False
    verbose: bool = False


def create_app() -> FastAPI:
    app = FastAPI(title="BB Scanner", version="1.0.0")

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
        if body.targets_upload_id:
            upload = store.get_upload(body.targets_upload_id)
            if not upload or upload.get("kind") != "targets":
                raise HTTPException(status_code=404, detail="target upload not found")
            try:
                targets.extend(read_upload_items(upload))
            except (ValueError, FileNotFoundError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        if not targets:
            return {"error": "no targets provided"}
        custom_paths = list(body.custom_paths)
        if body.wordlist_upload_id:
            upload = store.get_upload(body.wordlist_upload_id)
            if not upload or upload.get("kind") != "wordlist":
                raise HTTPException(status_code=404, detail="wordlist upload not found")
            try:
                custom_paths.extend(read_upload_items(upload))
            except (ValueError, FileNotFoundError) as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        cfg = ScanConfig(
            targets=list(dict.fromkeys(targets)),
            job_name=body.job_name.strip()[:120],
            targets_upload_id=body.targets_upload_id,
            wordlist_upload_id=body.wordlist_upload_id,
            threads=max(1, min(int(body.threads or 20), 500)),
            timeout=body.timeout,
            retries=body.retries,
            rate_limit_per_host=max(1.0, float(body.rate_limit_per_host or 50.0)),
            modules=body.modules,
            paths_mode=body.paths_mode,
            custom_paths=list(dict.fromkeys(custom_paths)),
            scope_notes=body.scope_notes,
            redact_secrets=body.redact_secrets,
            verify_tls=body.verify_tls,
            method_test_trace=body.method_test_trace,
            verbose=body.verbose,
            output_dir=str(ROOT / "output" / "scans"),
        )
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
    ) -> list[dict[str, Any]]:
        return store.get_findings(scan_id, severity=severity, ftype=type, module=module, q=q)

    @app.get("/api/scans/{scan_id}/logs")
    async def get_logs(
        scan_id: str,
        level: Optional[str] = None,
        module: Optional[str] = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        return store.get_logs(scan_id, level=level, module=module, limit=limit)

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

    async def _save_upload(file: UploadFile, kind: str) -> dict[str, Any]:
        content = await file.read()
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
            items = read_upload_items(row)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=410, detail=str(exc)) from exc
        return {**row, "preview": items[:50], "exists": True}

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
    async def get_results(scan_id: str, provider: Optional[str] = None) -> dict[str, Any]:
        row = store.get_scan(scan_id)
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

        secrets = list(secret_index.values())
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
                    "findings": bucket["findings"],
                }
            )

        # Ensure on-disk vulns/ tree exists for older scans / live debugging.
        out_dir = Path(row.get("output_dir") or (ROOT / "output" / "scans" / scan_id))
        vuln_files = {}
        try:
            bundle = write_vuln_artifacts(out_dir, findings)
            vuln_files = {
                "dir": bundle.get("dir"),
                "summary": bundle.get("summary"),
            }
        except Exception:
            vuln_files = {}

        return {
            "scan": row,
            "finding_count": len(findings),
            "by_severity": by_severity,
            "by_module": by_module,
            "secrets": secrets,
            "providers": [
                provider_metadata(provider_id, count)
                for provider_id, count in sorted(provider_counts.items())
            ],
            "vulnerable_hosts": vulnerable_hosts,
            "vuln_files": vuln_files,
            "findings": findings,
        }

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