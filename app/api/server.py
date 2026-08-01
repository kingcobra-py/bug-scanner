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
from app.core.vuln_artifacts import classify_finding, detection_method, host_from_finding, is_vuln_worthy, write_vuln_artifacts
from app.core.wordlists import save_uploaded_targets, save_uploaded_wordlist
from app.storage.db import ScanStore
from app.storage.models import ScanConfig

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
        if not targets:
            return {"error": "no targets provided"}
        cfg = ScanConfig(
            targets=targets,
            threads=max(1, min(int(body.threads or 20), 500)),
            timeout=body.timeout,
            retries=body.retries,
            rate_limit_per_host=max(1.0, float(body.rate_limit_per_host or 50.0)),
            modules=body.modules,
            paths_mode=body.paths_mode,
            custom_paths=body.custom_paths,
            scope_notes=body.scope_notes,
            verify_tls=body.verify_tls,
            method_test_trace=body.method_test_trace,
            verbose=body.verbose,
            output_dir=str(ROOT / "output" / "scans"),
        )
        engine.start_async(cfg)
        return {"id": cfg.scan_id, "status": "running"}

    @app.get("/api/scans")
    async def list_scans() -> list[dict[str, Any]]:
        return store.list_scans()

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
        return {"stopped": ok, "id": scan_id}

    @app.post("/api/wordlists/upload")
    async def upload_wordlist(
        file: UploadFile = File(...),
        mode: str = Form("merge"),
    ) -> dict[str, Any]:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        dest = UPLOAD_DIR / (file.filename or "custom_paths.txt")
        content = await file.read()
        paths = save_uploaded_wordlist(content, dest)
        return {"path": str(dest), "count": len(paths), "mode": mode, "paths_preview": paths[:50]}

    @app.post("/api/targets/upload")
    async def upload_targets(file: UploadFile = File(...)) -> dict[str, Any]:
        UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        dest = UPLOAD_DIR / (file.filename or "targets.txt")
        content = await file.read()
        targets = save_uploaded_targets(content, dest)
        return {
            "path": str(dest),
            "count": len(targets),
            "targets": targets,
            "targets_text": "\n".join(targets),
            "preview": targets[:50],
        }

    @app.get("/api/scans/{scan_id}/results")
    async def get_results(scan_id: str) -> dict[str, Any]:
        row = store.get_scan(scan_id)
        if not row:
            raise HTTPException(status_code=404, detail="scan not found")
        findings = store.get_findings(scan_id)
        by_severity: dict[str, int] = {}
        by_module: dict[str, int] = {}
        secrets: list[dict[str, Any]] = []
        host_map: dict[str, dict[str, Any]] = {}
        for f in findings:
            sev = f.get("severity") or "info"
            mod = f.get("module") or "unknown"
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_module[mod] = by_module.get(mod, 0) + 1
            extracted = f.get("extracted") or {}
            for secret in extracted.get("secrets") or []:
                secrets.append(
                    {
                        "kind": secret.get("kind"),
                        "value": secret.get("value"),
                        "source_url": secret.get("source_url") or f.get("url"),
                        "module": mod,
                        "title": f.get("title"),
                        "finding_id": f.get("id"),
                    }
                )
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