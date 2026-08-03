"""Thread-safe progress manager with rich CLI bars and snapshot export."""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict
from typing import Callable, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from app.storage.models import ProgressSnapshot
from app.utils.normalize import ensure_scheme


class ProgressManager:
    # Below this, per-call notify overhead (snapshot copy + subscriber
    # fanout) starts to dominate wall-clock time once hundreds of worker
    # threads call tick()/set_current() on every HTTP request. Counters
    # always update immediately; only the UI/DB fanout is coalesced.
    _NOTIFY_INTERVAL = 0.1

    def __init__(self, enable_cli: bool = True) -> None:
        self._lock = threading.Lock()
        self._snap = ProgressSnapshot()
        self._start = time.monotonic()
        self._subscribers: list[Callable[[ProgressSnapshot], None]] = []
        self._enable_cli = enable_cli
        self._console = Console(stderr=True)
        self._progress: Optional[Progress] = None
        self._overall_task: Optional[TaskID] = None
        self._module_task: Optional[TaskID] = None
        self._last_notify = 0.0
        # Request-rate tracking has its own lock: it's touched on every
        # single HTTP attempt (the highest-frequency call in the whole
        # engine), and giving it a dedicated lock means it never contends
        # with tick()/set_current()/add_hit() for the same mutex.
        self._request_lock = threading.Lock()
        self._request_times: deque[float] = deque()
        self._vulnerable_hosts: set[str] = set()

    def subscribe(self, callback: Callable[[ProgressSnapshot], None]) -> None:
        with self._lock:
            self._subscribers.append(callback)

    def _dispatch_locked(self, force: bool) -> tuple[Optional[ProgressSnapshot], list[Callable]]:
        """Call while holding self._lock. Returns (snapshot, subscribers) to
        notify outside the lock, or (None, []) if this call is coalesced."""
        now = time.monotonic()
        if not force and (now - self._last_notify) < self._NOTIFY_INTERVAL:
            return None, []
        self._last_notify = now
        return ProgressSnapshot(**asdict(self._snap)), list(self._subscribers)

    @staticmethod
    def _fanout(snap: Optional[ProgressSnapshot], subs: list[Callable]) -> None:
        if snap is None:
            return
        for cb in subs:
            try:
                cb(snap)
            except Exception:
                pass

    def _recompute_host_progress_locked(self) -> None:
        finished = self._snap.done + self._snap.failed
        self._snap.queued = max(self._snap.total - finished, 0)
        self._snap.percent = (finished / self._snap.total * 100.0) if self._snap.total else 0.0
        elapsed = max(time.monotonic() - self._start, 0.001)
        rate = finished / elapsed
        remaining = max(self._snap.total - finished, 0)
        self._snap.eta_seconds = (remaining / rate) if rate > 0 else None

    def start(self, total: int) -> None:
        with self._lock:
            self._snap.total = max(total, 0)
            self._snap.queued = max(total, 0)
            self._start = time.monotonic()
            if self._enable_cli:
                self._progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[bold blue]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TextColumn("{task.percentage:>3.0f}%"),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    console=self._console,
                    transient=False,
                )
                self._progress.start()
                self._overall_task = self._progress.add_task("hosts", total=max(total, 1))
                self._module_task = self._progress.add_task("module", total=1)
            snap, subs = self._dispatch_locked(force=True)
        self._fanout(snap, subs)

    def set_total(self, total: int) -> None:
        with self._lock:
            self._snap.total = max(total, 0)
            self._recompute_host_progress_locked()
            if self._progress and self._overall_task is not None:
                self._progress.update(self._overall_task, total=max(total, 1))
            snap, subs = self._dispatch_locked(force=True)
        self._fanout(snap, subs)

    def add_total(self, n: int) -> None:
        with self._lock:
            self._snap.total += n
            self._recompute_host_progress_locked()
            if self._progress and self._overall_task is not None:
                self._progress.update(self._overall_task, total=max(self._snap.total, 1))
            snap, subs = self._dispatch_locked(force=True)
        self._fanout(snap, subs)

    def set_current(self, target: str = "", module: str = "") -> None:
        with self._lock:
            if target:
                self._snap.current_target = target
            if module:
                self._snap.current_module = module
                if module not in self._snap.module_progress:
                    self._snap.module_progress[module] = {"done": 0, "total": 0, "hits": 0}
                if self._progress and self._module_task is not None:
                    self._progress.update(
                        self._module_task,
                        description=f"{module} @ {self._snap.current_target[:48]}",
                    )
            # Called once per target/module transition — high frequency at
            # scale, so this coalesces like tick() rather than forcing.
            snap, subs = self._dispatch_locked(force=False)
        self._fanout(snap, subs)

    def module_set_total(self, module: str, total: int) -> None:
        with self._lock:
            mp = self._snap.module_progress.setdefault(module, {"done": 0, "total": 0, "hits": 0})
            # Accumulate expected work across hosts instead of resetting —
            # otherwise Jobs module totals stay stuck at one host's path count.
            mp["total"] += max(int(total), 0)
            if self._progress and self._module_task is not None and self._snap.current_module == module:
                self._progress.update(self._module_task, total=max(mp["total"], 1), completed=mp["done"])
            snap, subs = self._dispatch_locked(force=False)
        self._fanout(snap, subs)

    def tick(self, success: bool = True, timeout: bool = False, module: str = "") -> None:
        """Record one HTTP/work-unit check. Does not advance host-level Done."""
        with self._lock:
            if timeout:
                self._snap.timeouts += 1
            mod = module or self._snap.current_module
            if mod:
                mp = self._snap.module_progress.setdefault(mod, {"done": 0, "total": 0, "hits": 0})
                mp["done"] += 1
            if self._progress and self._module_task is not None and mod:
                mp = self._snap.module_progress[mod]
                self._progress.update(self._module_task, completed=mp["done"], total=max(mp["total"], 1))
            # tick() fires once per HTTP path check — by far the highest
            # frequency call in the engine. Coalescing the fanout (not the
            # counters, which are always exact) is what keeps hundreds of
            # worker threads from serializing behind snapshot+dispatch on
            # every single request.
            snap, subs = self._dispatch_locked(force=False)
        self._fanout(snap, subs)

    def complete_target(self, success: bool = True) -> None:
        """Mark one domain/IP as fully finished (all selected modules, or dead)."""
        with self._lock:
            if success:
                self._snap.done += 1
            else:
                self._snap.failed += 1
            self._recompute_host_progress_locked()
            finished = self._snap.done + self._snap.failed
            if self._progress and self._overall_task is not None:
                self._progress.update(self._overall_task, completed=finished)
            snap, subs = self._dispatch_locked(force=True)
        self._fanout(snap, subs)

    def record_request(self) -> None:
        """Record one real HTTP attempt for accurate wire-level RPS."""
        now = time.monotonic()
        with self._request_lock:
            self._request_times.append(now)
            cutoff = now - 5.0
            while self._request_times and self._request_times[0] < cutoff:
                self._request_times.popleft()
            rps = len(self._request_times) / 5.0
        with self._lock:
            self._snap.requests += 1
            self._snap.rps = rps

    def add_hit(self, secrets: int = 0, module: str = "") -> None:
        with self._lock:
            self._snap.hits += 1
            self._snap.secrets += secrets
            mod = module or self._snap.current_module
            if mod:
                mp = self._snap.module_progress.setdefault(mod, {"done": 0, "total": 0, "hits": 0})
                mp["hits"] += 1
            # Hits are comparatively rare and high-value; always surface
            # them immediately rather than coalescing with tick() traffic.
            snap, subs = self._dispatch_locked(force=True)
        self._fanout(snap, subs)

    def note_vulnerable_host(self, url: str) -> None:
        """Count a unique host that produced at least one finding."""
        host = (urlparse(ensure_scheme(url or "")).netloc or "").lower()
        if not host:
            return
        with self._lock:
            if host in self._vulnerable_hosts:
                return
            self._vulnerable_hosts.add(host)
            self._snap.vulnerable_hosts = len(self._vulnerable_hosts)
            snap, subs = self._dispatch_locked(force=True)
        self._fanout(snap, subs)

    def snapshot(self) -> ProgressSnapshot:
        with self._lock:
            return ProgressSnapshot(**asdict(self._snap))

    def stop(self) -> None:
        with self._lock:
            if self._progress:
                self._progress.stop()
                self._progress = None
