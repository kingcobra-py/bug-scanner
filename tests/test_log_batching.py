"""Non-blocking, batched log persistence for scans at massive scale."""

from __future__ import annotations

import time

from app.storage.db import ScanStore


def test_add_log_does_not_block_caller(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    store.create_scan("scan-log", {"targets": ["a.example"]}, str(tmp_path / "scan-log"))

    t0 = time.monotonic()
    for i in range(500):
        store.add_log("scan-log", {"message": f"line {i}", "level": "INFO", "module": "engine"})
    elapsed = time.monotonic() - t0
    # 500 synchronous SQLite commits would take far longer than this; the
    # call must only enqueue, never touch the database directly.
    assert elapsed < 0.5

    store.flush_logs()
    rows = store.get_logs("scan-log", limit=1000)
    assert len(rows) == 500
    assert rows[0]["message"] == "line 0"
    assert rows[-1]["message"] == "line 499"


def test_add_log_batches_across_many_threads(tmp_path):
    import threading

    store = ScanStore(tmp_path / "scanner.db")
    store.create_scan("scan-concurrent", {"targets": ["a.example"]}, str(tmp_path / "scan-concurrent"))

    def worker(n):
        for i in range(50):
            store.add_log("scan-concurrent", {"message": f"t{n}-{i}", "level": "DEBUG", "module": "wordpress"})

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    store.flush_logs()
    rows = store.get_logs("scan-concurrent", limit=2000)
    assert len(rows) == 1000


def test_flush_logs_returns_once_pending_writes_are_committed(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    store.create_scan("scan-flush", {"targets": ["a.example"]}, str(tmp_path / "scan-flush"))
    store.add_log("scan-flush", {"message": "hello", "level": "INFO", "module": "engine"})
    store.flush_logs(timeout=2.0)
    assert store.get_logs("scan-flush") == [
        {"timestamp": "", "level": "INFO", "module": "engine", "message": "hello"}
    ]
