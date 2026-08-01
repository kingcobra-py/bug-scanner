"""At 10M+ target scale, per-target lifecycle chatter must stay off by
default — only genuine anomalies and hits should reach the log table."""

from __future__ import annotations

from app.core.engine import ScanEngine
from app.core.http_client import HttpResponse
from app.core.progress import ProgressManager
from app.storage.db import ScanStore
from app.storage.models import ScanConfig
from app.utils.logger import add_log_subscriber, get_scan_logger, remove_log_subscriber


class AlwaysDeadClient:
    def probe_live(self, url):
        return HttpResponse(
            url=url,
            status_code=0,
            headers={},
            text="",
            content=b"",
            elapsed=0.0,
            error="timeout:ReadTimeout",
            method="GET",
        )


def test_dead_target_logs_stay_quiet_by_default(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    engine = ScanEngine(store=store, enable_cli_progress=False)
    config = ScanConfig(targets=[], output_dir=str(tmp_path), verbose=False)
    progress = ProgressManager(enable_cli=False)
    progress.start(1)
    logger = get_scan_logger("scan-quiet", tmp_path, module="engine", level="INFO")

    def forward(event: dict) -> None:
        store.add_log(event.get("scan_id", "scan-quiet"), event)

    add_log_subscriber(forward)
    try:
        chosen = engine._prepare_target(AlwaysDeadClient(), "http://dead.example", config, progress, logger)
    finally:
        remove_log_subscriber(forward)

    assert chosen == []
    store.flush_logs()
    # A default (non-verbose) scan must not persist a DB row per dead target;
    # at 10M+ targets that alone was enough to make the log writer the
    # bottleneck. Verbose mode intentionally still logs everything at DEBUG.
    assert store.get_logs("scan-quiet") == []


def test_verbose_mode_still_records_dead_target_detail(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    engine = ScanEngine(store=store, enable_cli_progress=False)
    config = ScanConfig(targets=[], output_dir=str(tmp_path), verbose=True)
    progress = ProgressManager(enable_cli=False)
    progress.start(1)
    logger = get_scan_logger("scan-verbose", tmp_path, module="engine", level="DEBUG")

    def forward(event: dict) -> None:
        store.add_log(event.get("scan_id", "scan-verbose"), event)

    add_log_subscriber(forward)
    try:
        engine._prepare_target(AlwaysDeadClient(), "http://dead.example", config, progress, logger)
    finally:
        remove_log_subscriber(forward)

    store.flush_logs()
    rows = store.get_logs("scan-verbose")
    assert any("offline" in row["message"] for row in rows)
