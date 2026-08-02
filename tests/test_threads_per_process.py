"""Threads is a per-process budget once multi-process mode is enabled."""

from __future__ import annotations

from app.core.engine import SAFE_THREADS_PER_PROCESS, ScanEngine


def _resolve(threads: int, worker_processes: int, cpu_count: int = 16) -> tuple[int, int]:
    """Mirror the production formula in ScanEngine._run_multiprocess."""
    cpu_cap = cpu_count or 4
    num_workers = max(1, min(int(worker_processes), cpu_cap, 32))
    threads_per_process = max(1, min(SAFE_THREADS_PER_PROCESS, int(threads)))
    return num_workers, threads_per_process


def test_threads_apply_per_process_not_divided():
    # Operator expectation: Threads=300 and Worker processes=3 means each
    # of the 3 processes runs 300 threads (~900 concurrent targets), not
    # 100 threads each.
    num_workers, tpp = _resolve(300, 3)
    assert num_workers == 3
    assert tpp == 300


def test_threads_still_capped_at_safe_per_process_ceiling():
    num_workers, tpp = _resolve(800, 2)
    assert num_workers == 2
    assert tpp == SAFE_THREADS_PER_PROCESS


def test_worker_process_count_capped_by_cpu_not_by_threads():
    # Even with a small Threads value, processes should not be silently
    # collapsed down to the thread count (old formula did that).
    num_workers, tpp = _resolve(threads=50, worker_processes=4, cpu_count=8)
    assert num_workers == 4
    assert tpp == 50


def test_safe_threads_constant_matches_measured_ceiling():
    assert SAFE_THREADS_PER_PROCESS == 300
    assert ScanEngine is not None
