"""Spawned worker-process entry point for multi-process scanning.

Each worker gets its own fresh Python interpreter (via the "spawn" start
method, never "fork") so it never inherits the main process's live
SQLAlchemy engine, background log-writer thread, or asyncio event loop --
all of which are unsafe to share across a fork(). It builds everything it
needs from scratch:

- its own ScanStore pointed at the *same* SQLite file (safe under WAL;
  each worker's log/finding/progress writes land in the one shared table)
- its own HttpClient / ProgressManager / ScanEngine instance
- a static, stateless shard of the target stream (every worker reads the
  same source independently and takes every Nth line), so no work-
  distribution queue or shared state is needed to split the work fairly

A lightweight notify queue relays the same finding/log/progress events
back to the main process purely so the dashboard can keep pushing live
websocket updates. Losing that queue never loses data -- persistence
already happened directly via each worker's own SQLite writes.
"""

from __future__ import annotations

import queue as queue_mod
import time
from dataclasses import asdict
from pathlib import Path
from typing import Iterator

from app.core.engine import ScanEngine
from app.core.http_client import HttpClient
from app.core.progress import ProgressManager
from app.core.wordlists import iter_target_lines, load_wordlist
from app.storage.db import ScanStore
from app.storage.models import Finding, ScanConfig, ScanContext
from app.utils.logger import add_log_subscriber, get_scan_logger, remove_log_subscriber
from app.utils.normalize import normalize_target


def iter_sharded_targets(
    config: ScanConfig,
    worker_id: int,
    num_workers: int,
    *,
    skip_indices: set[int] | None = None,
) -> Iterator[tuple[int, str]]:
    """Deterministic static sharding by stream position.

    Every worker iterates the exact same source (inline list, then the
    streamed targets_path file) independently and keeps only the Nth
    items assigned to it. Yields ``(absolute_index, url)`` so callers can
    checkpoint completions for resume-after-reboot.
    """
    skip = skip_indices or set()
    index = 0
    for target in config.targets:
        normalized = normalize_target((target or "").strip())
        if normalized:
            if index % num_workers == worker_id and index not in skip:
                yield index, normalized
            index += 1
    if config.targets_path:
        for target in iter_target_lines(config.targets_path):
            normalized = normalize_target(target)
            if normalized:
                if index % num_workers == worker_id and index not in skip:
                    yield index, normalized
                index += 1


def run_worker(
    config: ScanConfig,
    worker_id: int,
    num_workers: int,
    threads_per_process: int,
    db_path: str,
    notify_queue,
    stop_event,
) -> None:
    scan_id = config.scan_id
    out_dir = Path(config.output_dir) / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)

    worker_store = ScanStore(db_path)
    engine = ScanEngine(store=worker_store, enable_cli_progress=False)
    progress = ProgressManager(enable_cli=False)
    logger = get_scan_logger(scan_id, out_dir, module="engine", level="DEBUG" if config.verbose else "INFO")

    def _log_cb(event: dict) -> None:
        if event.get("scan_id") != scan_id:
            return
        try:
            worker_store.add_log(scan_id, event)
        except Exception:
            pass
        try:
            notify_queue.put_nowait({"type": "log", "data": event})
        except Exception:
            pass

    add_log_subscriber(_log_cb)

    last_notify = {"t": 0.0}

    def _prog_cb(snap, force: bool = False) -> None:
        now = time.monotonic()
        force = force or bool(getattr(snap, "percent", 0) >= 100 or stop_event.is_set())
        if not force and (now - last_notify["t"]) < 0.4:
            return
        last_notify["t"] = now
        try:
            notify_queue.put_nowait({"type": "worker_progress", "worker_id": worker_id, "data": asdict(snap)})
        except Exception:
            pass

    progress.subscribe(_prog_cb)

    http = HttpClient(
        timeout=config.timeout,
        connect_timeout=config.connect_timeout,
        retries=config.retries,
        verify_tls=config.verify_tls,
        proxy=config.proxy,
        headers=config.headers,
        max_body_bytes=config.max_body_bytes,
        rate_limit_per_host=max(float(config.rate_limit_per_host or 50.0), 1.0),
        on_request=progress.record_request,
        max_connections=max(256, threads_per_process * 2),
    )

    persisted_ids: set[str] = set()

    def _persist_finding(fd: dict) -> None:
        fid = fd.get("id") or ""
        if fid and fid in persisted_ids:
            return
        if fid:
            persisted_ids.add(fid)
        try:
            worker_store.add_finding(scan_id, fd)
        except Exception:
            pass
        try:
            notify_queue.put_nowait({"type": "finding", "data": fd})
        except Exception:
            pass
        try:
            with (out_dir / "hits.jsonl").open("a", encoding="utf-8") as fh:
                import json as _json

                fh.write(_json.dumps(fd, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _live_finding(finding: Finding) -> None:
        _persist_finding(finding.to_dict())

    def _on_target_done(findings: list[Finding]) -> None:
        for finding in findings:
            _persist_finding(finding.to_dict())

    if config.wordlist_path:
        config.custom_paths = list(dict.fromkeys([*config.custom_paths, *load_wordlist(config.wordlist_path)]))
    modules = engine._build_modules(config)

    ctx = ScanContext(
        config=config,
        output_dir=out_dir,
        stop_event=stop_event,
        progress=progress,
        store=worker_store,
        http=http,
        logger=logger,
        # ===== NEW: pass exploit flags from config =====
        exploit_enabled=config.exploit_enabled,
        exploit_command=config.exploit_command,
        exploit_all=config.exploit_all,
    )

    try:
        from app.core.checkpoint import CheckpointWriter, load_completed_indices

        # Host-level progress for this shard (ceil split of the target list).
        target_count = int(config.target_count or len(config.targets) or 0)
        shard_hosts = max((target_count + num_workers - 1) // num_workers, 1)
        skip_indices = load_completed_indices(out_dir)
        # Approximate how many of this shard were already finished.
        shard_done = sum(1 for idx in skip_indices if idx % num_workers == worker_id)
        progress.start(shard_hosts)
        if shard_done:
            progress.seed_completed(min(shard_done, shard_hosts))
        checkpoint = CheckpointWriter(out_dir)

        from concurrent.futures import ThreadPoolExecutor

        pool = ThreadPoolExecutor(max_workers=max(1, threads_per_process))
        try:
            max_inflight = max(threads_per_process * 3, threads_per_process)
            engine._drain_pipeline(
                targets=iter_sharded_targets(
                    config, worker_id, num_workers, skip_indices=skip_indices
                ),
                modules=modules,
                ctx=ctx,
                pool=pool,
                max_inflight=max_inflight,
                stop_event=stop_event,
                on_finding=_live_finding,
                on_target_done=_on_target_done,
                logger=logger,
                on_index_done=checkpoint.mark,
            )
        finally:
            # Closing the shared client first aborts in-flight socket reads so
            # stop doesn't leave workers pinned on huge/slow downloads.
            if stop_event.is_set():
                try:
                    http.close()
                except Exception:
                    pass
            pool.shutdown(wait=not stop_event.is_set(), cancel_futures=stop_event.is_set())
    except Exception as e:
        logger.error("worker %d failed: %s", worker_id, e)
    finally:
        # Push one final forced snapshot so the aggregate isn't stuck at a
        # slightly-stale count from the last throttled update.
        try:
            _prog_cb(progress.snapshot(), force=True)
        except Exception:
            pass
        progress.stop()
        remove_log_subscriber(_log_cb)
        http.close()
        try:
            worker_store.flush_logs(timeout=2.0)
        except Exception:
            pass
