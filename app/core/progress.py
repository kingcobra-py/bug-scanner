"""Thread-safe progress manager with rich CLI bars and snapshot export."""

from __future__ import annotations

import threading
import time
from dataclasses import asdict
from typing import Callable, Optional

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


class ProgressManager:
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
        self._request_times: list[float] = []

    def subscribe(self, callback: Callable[[ProgressSnapshot], None]) -> None:
        with self._lock:
            self._subscribers.append(callback)

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
                self._overall_task = self._progress.add_task("overall", total=max(total, 1))
                self._module_task = self._progress.add_task("module", total=1)
        self._notify()

    def set_total(self, total: int) -> None:
        with self._lock:
            self._snap.total = max(total, 0)
            self._snap.queued = max(total - self._snap.done - self._snap.failed, 0)
            if self._progress and self._overall_task is not None:
                self._progress.update(self._overall_task, total=max(total, 1))
        self._notify()

    def add_total(self, n: int) -> None:
        with self._lock:
            self._snap.total += n
            self._snap.queued += n
            if self._progress and self._overall_task is not None:
                self._progress.update(self._overall_task, total=max(self._snap.total, 1))
        self._notify()

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
        self._notify()

    def module_set_total(self, module: str, total: int) -> None:
        with self._lock:
            mp = self._snap.module_progress.setdefault(module, {"done": 0, "total": 0, "hits": 0})
            mp["total"] = total
            if self._progress and self._module_task is not None and self._snap.current_module == module:
                self._progress.update(self._module_task, total=max(total, 1), completed=mp["done"])
        self._notify()

    def tick(self, success: bool = True, timeout: bool = False, module: str = "") -> None:
        now = time.monotonic()
        with self._lock:
            self._snap.requests += 1
            self._request_times.append(now)
            # keep last 5s window
            cutoff = now - 5.0
            self._request_times = [t for t in self._request_times if t >= cutoff]
            self._snap.rps = len(self._request_times) / 5.0
            if timeout:
                self._snap.timeouts += 1
            if success:
                self._snap.done += 1
            else:
                self._snap.failed += 1
            finished = self._snap.done + self._snap.failed
            self._snap.queued = max(self._snap.total - finished, 0)
            self._snap.percent = (finished / self._snap.total * 100.0) if self._snap.total else 0.0
            elapsed = max(now - self._start, 0.001)
            rate = finished / elapsed
            remaining = max(self._snap.total - finished, 0)
            self._snap.eta_seconds = (remaining / rate) if rate > 0 else None
            mod = module or self._snap.current_module
            if mod:
                mp = self._snap.module_progress.setdefault(mod, {"done": 0, "total": 0, "hits": 0})
                mp["done"] += 1
            if self._progress and self._overall_task is not None:
                self._progress.update(self._overall_task, completed=finished)
                if self._module_task is not None and mod:
                    mp = self._snap.module_progress[mod]
                    self._progress.update(self._module_task, completed=mp["done"], total=max(mp["total"], 1))
        self._notify()

    def add_hit(self, secrets: int = 0, module: str = "") -> None:
        with self._lock:
            self._snap.hits += 1
            self._snap.secrets += secrets
            mod = module or self._snap.current_module
            if mod:
                mp = self._snap.module_progress.setdefault(mod, {"done": 0, "total": 0, "hits": 0})
                mp["hits"] += 1
        self._notify()

    def snapshot(self) -> ProgressSnapshot:
        with self._lock:
            return ProgressSnapshot(**asdict(self._snap))

    def stop(self) -> None:
        with self._lock:
            if self._progress:
                self._progress.stop()
                self._progress = None

    def _notify(self) -> None:
        snap = self.snapshot()
        with self._lock:
            subs = list(self._subscribers)
        for cb in subs:
            try:
                cb(snap)
            except Exception:
                pass