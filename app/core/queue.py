"""Simple thread-safe work queue helpers."""

from __future__ import annotations

import queue
import threading
from typing import Any, Callable, Iterable, Optional


class TaskQueue:
    def __init__(self) -> None:
        self._q: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self._submitted = 0
        self._completed = 0

    def put(self, item: Any) -> None:
        with self._lock:
            self._submitted += 1
        self._q.put(item)

    def put_many(self, items: Iterable[Any]) -> int:
        n = 0
        for item in items:
            self.put(item)
            n += 1
        return n

    def get(self, timeout: Optional[float] = None) -> Any:
        return self._q.get(timeout=timeout)

    def task_done(self) -> None:
        with self._lock:
            self._completed += 1
        self._q.task_done()

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                "submitted": self._submitted,
                "completed": self._completed,
                "pending": self._q.qsize(),
            }

    def join(self) -> None:
        self._q.join()


def map_threaded(
    fn: Callable[[Any], Any],
    items: Iterable[Any],
    workers: int = 20,
    stop_event: Optional[threading.Event] = None,
) -> list[Any]:
    from concurrent.futures import ThreadPoolExecutor, as_completed

    results: list[Any] = []
    item_list = list(items)
    if not item_list:
        return results
    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futures = []
        for item in item_list:
            if stop_event and stop_event.is_set():
                break
            futures.append(ex.submit(fn, item))
        for fut in as_completed(futures):
            if stop_event and stop_event.is_set():
                break
            try:
                results.append(fut.result())
            except Exception as e:
                results.append(e)
    return results