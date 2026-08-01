"""Colored console + rotating per-scan file logs."""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Callable, Optional

from rich.console import Console
from rich.logging import RichHandler

_console = Console(stderr=True)
_lock = threading.Lock()
_subscribers: list[Callable[[dict], None]] = []
_scan_loggers: dict[str, logging.Logger] = {}


def add_log_subscriber(callback: Callable[[dict], None]) -> None:
    with _lock:
        _subscribers.append(callback)


def remove_log_subscriber(callback: Callable[[dict], None]) -> None:
    with _lock:
        if callback in _subscribers:
            _subscribers.remove(callback)


def _emit_event(event: dict) -> None:
    with _lock:
        subs = list(_subscribers)
    for cb in subs:
        try:
            cb(event)
        except Exception:
            pass


class ScanLogAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        module = self.extra.get("module", "engine")
        scan_id = self.extra.get("scan_id", "-")
        return f"[{module}] {msg}", kwargs

    def hit(self, url: str, conf: float = 0.0, **kwargs) -> None:
        self.info("HIT %s conf=%.2f", url, conf, **kwargs)

    def log(self, level, msg, *args, **kwargs) -> None:
        if not self.isEnabledFor(level):
            return
        event_fields = kwargs.pop("_event_fields", {})
        super().log(level, msg, *args, **kwargs)
        try:
            message = msg % args if args else str(msg)
        except Exception:
            message = str(msg)
        _emit_event(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": logging.getLevelName(level),
                "module": self.extra.get("module", "engine"),
                "scan_id": self.extra.get("scan_id", "-"),
                "message": message,
                **event_fields,
            }
        )

    def event(self, level: str, message: str, **fields) -> None:
        lvl = getattr(logging, level.upper(), logging.INFO)
        self.log(lvl, message, _event_fields=fields)


def setup_root_logger(level: str = "INFO") -> None:
    root = logging.getLogger("bbscanner")
    if root.handlers:
        root.setLevel(getattr(logging, level.upper(), logging.INFO))
        return
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    rich = RichHandler(
        console=_console,
        show_time=True,
        show_path=False,
        markup=False,
        rich_tracebacks=False,
    )
    rich.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(rich)


def get_scan_logger(
    scan_id: str,
    output_dir: Path,
    module: str = "engine",
    level: str = "INFO",
) -> ScanLogAdapter:
    setup_root_logger(level)
    key = f"{scan_id}:{module}"
    with _lock:
        if scan_id not in _scan_loggers:
            logger = logging.getLogger(f"bbscanner.scan.{scan_id}")
            logger.setLevel(getattr(logging, level.upper(), logging.INFO))
            logger.propagate = True
            log_path = Path(output_dir) / "scan.log"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            fh = RotatingFileHandler(log_path, maxBytes=5_000_000, backupCount=3)
            fh.setFormatter(
                logging.Formatter(
                    "[%(asctime)s] [%(levelname)s] %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S",
                )
            )
            logger.addHandler(fh)
            _scan_loggers[scan_id] = logger
        base = _scan_loggers[scan_id]
    return ScanLogAdapter(base, {"scan_id": scan_id, "module": module})


def get_module_logger(scan_id: str, module: str, output_dir: Path, level: str = "INFO") -> ScanLogAdapter:
    return get_scan_logger(scan_id, output_dir, module=module, level=level)