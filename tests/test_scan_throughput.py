"""End-to-end throughput regression: a real scan over a mix of live and dead
hosts should stay fast and quiet at scale (the combined fix for slow RPS)."""

from __future__ import annotations

import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from app.core.engine import ScanEngine
from app.storage.db import ScanStore
from app.storage.models import ScanConfig


class TinyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


def test_scan_with_many_dead_targets_stays_fast_and_quiet(tmp_path):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), TinyHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    live_base = f"http://127.0.0.1:{httpd.server_address[1]}"

    # Port 1 is reserved and nothing listens there locally, so these fail
    # fast with connection-refused rather than a real network timeout —
    # exercising the same "mostly dead targets" shape as a real recon list
    # without needing external network access in CI.
    dead_targets = [f"http://127.0.0.1:1/{i}" for i in range(40)]
    targets = [live_base, *dead_targets]

    out = tmp_path / "scans"
    store = ScanStore(out / "t.db")
    engine = ScanEngine(store=store, enable_cli_progress=False)
    cfg = ScanConfig(
        targets=targets,
        threads=20,
        timeout=2.0,
        retries=1,
        modules=["git"],
        output_dir=str(out),
        formats=["json"],
        probe_both_schemes=False,
        verbose=False,
    )

    t0 = time.monotonic()
    report = engine.run(cfg)
    elapsed = time.monotonic() - t0
    httpd.shutdown()

    assert "error" not in report or not report.get("error")
    # Dead hosts fail on connect (no retry wasted on a probe that will never
    # succeed) instead of each burning timeout*retries sequentially.
    assert elapsed < 10.0

    store.flush_logs()
    logs = store.get_logs(cfg.scan_id, limit=5000)
    # 40 dead-target lifecycle messages must NOT reach the DB by default;
    # only the handful of scan-level/engine milestones should.
    assert len(logs) < 10, f"expected quiet logging by default, got {len(logs)} rows"
