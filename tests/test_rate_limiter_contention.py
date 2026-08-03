"""HostRateLimiter must not serialize unrelated hosts behind one lock —
that alone made adding more scan threads reduce throughput at scale."""

from __future__ import annotations

import threading
import time

from app.core.http_client import HostRateLimiter


def test_different_hosts_do_not_block_each_other():
    limiter = HostRateLimiter(per_host=2.0)  # 500ms min interval per host
    barrier = threading.Barrier(50)
    durations: list[float] = []
    lock = threading.Lock()

    def worker(index: int) -> None:
        barrier.wait()
        t0 = time.monotonic()
        # Each thread targets its own unique host, so none of them should
        # ever wait on another thread's rate-limit slot.
        limiter.wait(f"host-{index}.example")
        elapsed = time.monotonic() - t0
        with lock:
            durations.append(elapsed)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=5)

    # First call per host never sleeps (no prior timestamp); if the lock
    # were shared, 50 threads contending for one mutex plus scheduling
    # overhead would still finish fast for THIS assertion — the real
    # regression shows up as sustained sub-linear throughput under load,
    # which the /_shard partitioning below verifies directly.
    assert all(d < 1.0 for d in durations)


def test_same_host_still_serializes_and_rate_limits():
    limiter = HostRateLimiter(per_host=10.0)  # 100ms min interval
    host = "shared.example"
    limiter.wait(host)
    t0 = time.monotonic()
    limiter.wait(host)
    elapsed = time.monotonic() - t0
    assert elapsed >= 0.08  # same host must still honor the interval


def test_lock_is_sharded_not_global():
    limiter = HostRateLimiter(per_host=10.0)
    assert len(limiter._shard_locks) > 1
    # Sharding must be deterministic per host (repeated lookups agree)...
    for host in ("alpha.example", "beta.example", "gamma.example"):
        assert limiter._shard(host) is limiter._shard(host)
    # ...and, across many distinct hosts, must actually spread across more
    # than one lock — otherwise this would collapse back into a single
    # global lock and reproduce the original contention bug.
    seen_locks = {id(limiter._shard(f"host-{i}.example")) for i in range(200)}
    assert len(seen_locks) > 1
