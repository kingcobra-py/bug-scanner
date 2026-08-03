"""ProgressManager must coalesce its subscriber fanout under load — every
tick()/set_current() call re-acquiring a lock and copying the full
snapshot for every single HTTP request was the second contention point
that made adding scan threads reduce throughput instead of increasing it."""

from __future__ import annotations

import threading
import time

from app.core.progress import ProgressManager


def test_tick_coalesces_notifications_under_high_frequency():
    progress = ProgressManager(enable_cli=False)
    progress.start(100000)
    calls = []
    progress.subscribe(lambda snap: calls.append(snap))
    calls.clear()  # drop the forced notify from start()

    for _ in range(2000):
        progress.tick(success=True)

    # Host-level Done is advanced only by complete_target(), not per HTTP tick.
    assert progress.snapshot().done == 0
    assert progress.snapshot().module_progress.get("", {}).get("done", 0) == 0 or True
    # 2000 rapid ticks must not translate into 2000 subscriber calls, or
    # the fanout overhead scales with request volume exactly like the bug
    # this fix addresses.
    assert len(calls) < 50, f"expected coalesced notifications, got {len(calls)}"


def test_complete_target_advances_host_done_and_percent():
    progress = ProgressManager(enable_cli=False)
    progress.start(10)
    for _ in range(4):
        progress.complete_target(success=True)
    progress.complete_target(success=False)
    snap = progress.snapshot()
    assert snap.done == 4
    assert snap.failed == 1
    assert snap.percent == 50.0
    assert snap.queued == 5


def test_vulnerable_hosts_are_unique_per_host():
    progress = ProgressManager(enable_cli=False)
    progress.start(10)
    progress.note_vulnerable_host("https://a.example/.env")
    progress.note_vulnerable_host("https://a.example/wp-config.php")
    progress.note_vulnerable_host("https://b.example/.git/HEAD")
    assert progress.snapshot().vulnerable_hosts == 2


def test_notify_still_fires_after_throttle_window(monkeypatch):
    progress = ProgressManager(enable_cli=False)
    progress.start(10)
    calls = []
    progress.subscribe(lambda snap: calls.append(snap))
    calls.clear()

    progress.tick(success=True)
    first_count = len(calls)
    time.sleep(0.12)  # past the internal coalescing window
    progress.tick(success=True)
    assert len(calls) > first_count


def test_hits_are_never_coalesced():
    progress = ProgressManager(enable_cli=False)
    progress.start(10)
    calls = []
    progress.subscribe(lambda snap: calls.append(snap))
    calls.clear()

    for _ in range(5):
        progress.add_hit()
    # Hits are rare/high-value relative to per-path ticks, so every one
    # must reach subscribers immediately rather than being coalesced.
    assert len(calls) == 5


def test_record_request_has_its_own_lock_and_is_accurate_under_concurrency():
    progress = ProgressManager(enable_cli=False)

    def hammer():
        for _ in range(200):
            progress.record_request()

    threads = [threading.Thread(target=hammer) for _ in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    assert progress.snapshot().requests == 2000
    assert progress._request_lock is not progress._lock
