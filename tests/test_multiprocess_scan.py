"""Integration coverage for real multi-process scanning: spawns actual OS
processes (via engine.run()/start_async() exactly as production does) and
verifies findings/progress/stop all work correctly end-to-end across the
process boundary, not just within one shared-memory test process."""

from __future__ import annotations

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from app.core.engine import ScanEngine
from app.storage.db import ScanStore
from app.storage.models import ScanConfig


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path == "/.git/HEAD":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/main\n")
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"root")


def _run_server() -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def test_multiprocess_scan_persists_findings_and_completes(tmp_path):
    httpd = _run_server()
    live_base = f"http://127.0.0.1:{httpd.server_address[1]}"
    # A handful of unreachable hosts so both worker processes get a mix of
    # live and dead targets to shard across, not just the one live host.
    dead_targets = [f"http://127.0.0.1:1/{i}" for i in range(10)]
    targets = [live_base, *dead_targets]

    out = tmp_path / "scans"
    store = ScanStore(out / "t.db")
    engine = ScanEngine(store=store, enable_cli_progress=False)
    cfg = ScanConfig(
        targets=targets,
        threads=4,
        worker_processes=2,
        timeout=2.0,
        connect_timeout=1.0,
        retries=0,
        modules=["git"],
        output_dir=str(out),
        formats=["json"],
        probe_both_schemes=False,
        verbose=False,
    )

    report = engine.run(cfg)
    httpd.shutdown()

    assert "error" not in report or not report.get("error"), report.get("error")

    row = store.get_scan(cfg.scan_id)
    assert row is not None
    assert row["status"] == "completed"

    findings = store.get_findings(cfg.scan_id)
    assert any("git" in (f.get("type") or "").lower() or "git" in (f.get("title") or "").lower() for f in findings)

    progress = row["progress"]
    assert progress["done"] + progress["failed"] > 0
    # Persisted by the orchestrator after both worker processes exit.
    assert progress["percent"] == 100.0


def test_multiprocess_scan_stop_propagates_across_processes(tmp_path):
    # Enough dead targets that the scan is still running when stop() fires.
    targets = [f"http://127.0.0.1:1/{i}" for i in range(300)]
    out = tmp_path / "scans"
    store = ScanStore(out / "t.db")
    engine = ScanEngine(store=store, enable_cli_progress=False)
    cfg = ScanConfig(
        targets=targets,
        threads=4,
        worker_processes=2,
        timeout=3.0,
        connect_timeout=2.0,
        retries=0,
        modules=["git"],
        output_dir=str(out),
        formats=["json"],
        probe_both_schemes=False,
        verbose=False,
    )

    engine.start_async(cfg)
    # Give the spawn+startup sequence a brief moment, then request a stop
    # while workers are very likely still mid-scan.
    time.sleep(0.5)
    assert engine.is_active(cfg.scan_id) is True
    stopped = engine.stop(cfg.scan_id)
    assert stopped is True

    deadline = time.monotonic() + 20.0
    status = None
    while time.monotonic() < deadline:
        row = store.get_scan(cfg.scan_id)
        status = row.get("status") if row else None
        if status in {"stopped", "completed", "failed"}:
            break
        time.sleep(0.2)
    assert status == "stopped", f"expected scan to stop promptly, last status={status}"
    assert engine.is_active(cfg.scan_id) is False
