"""Thread-based scan orchestrator, with an opt-in multi-process mode."""

from __future__ import annotations

import csv
import json
import multiprocessing
import os
import queue as queue_mod
import random
import threading
import time
import traceback
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Optional
from urllib.parse import urlparse

from app.core.fingerprint import fingerprint_target
from app.core.http_client import HttpClient
from app.core.progress import ProgressManager
from app.core.vuln_artifacts import write_vuln_artifacts
from app.core.wordlists import iter_target_lines, load_wordlist
from app.modules.config_env import ConfigEnvModule
from app.modules.base import stream_findings
from app.modules.git_exposure import GitExposureModule
from app.modules.joomla import JoomlaModule
from app.modules.js_secrets import JsSecretsModule
from app.modules.method_tester import MethodTesterModule
from app.modules.path_bruteforce import PathBruteforceModule
from app.modules.react2shell import ReactModule
from app.modules.wordpress import WordPressModule
from app.storage.db import ScanStore
from app.storage.models import Finding, ProgressSnapshot, ScanConfig, ScanContext, TargetContext
from app.utils.dedupe import dedupe_findings
from app.utils.logger import get_scan_logger, add_log_subscriber, remove_log_subscriber
from app.utils.normalize import normalize_target, origin_variants

# Measured live on the target box: raising *thread* count past ~300-400 in a
# single Python process reduced throughput (GIL contention) and, at 800
# threads, twice made the dashboard's own API hang for 10+ seconds. Multiple
# OS *processes* is the real fix -- each gets its own GIL, so this is the
# per-process thread ceiling multi-process mode is built around.
SAFE_THREADS_PER_PROCESS = 300


MODULE_ORDER = [
    "git",
    "js",
    "config",
    "path",
    "methods",
    "wordpress",
    "joomla",
    "react",
]


class ScanEngine:
    def __init__(
        self,
        store: Optional[ScanStore] = None,
        on_finding: Optional[Callable[[str, dict], None]] = None,
        on_progress: Optional[Callable[[str, dict], None]] = None,
        on_log: Optional[Callable[[str, dict], None]] = None,
        enable_cli_progress: bool = True,
    ) -> None:
        self.store = store or ScanStore()
        self.on_finding = on_finding
        self.on_progress = on_progress
        self.on_log = on_log
        self.enable_cli_progress = enable_cli_progress
        self._stop_events: dict[str, threading.Event] = {}
        self._threads: dict[str, threading.Thread] = {}
        self._executors: dict[str, list[ThreadPoolExecutor]] = {}
        self._clients: dict[str, HttpClient] = {}
        self._lock = threading.Lock()
        self._artifact_lock = threading.Lock()
        self._last_artifact_write: dict[str, float] = {}
        # Multi-process bookkeeping is kept separate from the single-process
        # dicts above so stop()/is_active() can support either mode without
        # the two ever being confused for the same scan_id.
        self._process_stop_events: dict[str, "multiprocessing.synchronize.Event"] = {}
        self._processes: dict[str, list[multiprocessing.Process]] = {}

    def stop(self, scan_id: str) -> bool:
        proc_stop = self._process_stop_events.get(scan_id)
        if proc_stop is not None:
            # Signal only and return immediately. Joining worker processes
            # here would block this call for however long they take to wind
            # down (up to several seconds per process) -- and this method is
            # invoked directly from an async API handler, so any blocking
            # here freezes the whole dashboard, not just this request. The
            # actual join/terminate happens in _run_multiprocess's own
            # background thread, which is where blocking is safe.
            proc_stop.set()
            self.store.update_status(scan_id, "stopping")
            return True
        ev = self._stop_events.get(scan_id)
        if not ev:
            # A server restart can leave a persisted "running" row with no
            # worker behind it. Mark that orphan stopped instead of leaving an
            # unresponsive Stop button in the dashboard.
            row = self.store.get_scan(scan_id)
            if row and row.get("status") in {"pending", "running", "stopping"}:
                self.store.update_status(scan_id, "stopped")
                return True
            return False
        ev.set()
        self.store.update_status(scan_id, "stopping")
        with self._lock:
            executors = list(self._executors.get(scan_id, []))
            client = self._clients.get(scan_id)
        for executor in executors:
            executor.shutdown(wait=False, cancel_futures=True)
        if client:
            client.close()
        return True

    def is_active(self, scan_id: str) -> bool:
        if scan_id in self._process_stop_events:
            # Presence alone spans the full lifetime (registered before the
            # thread starts, removed only after run() fully completes), so
            # this stays correct even in the brief window before individual
            # worker processes have actually been spawned.
            return True
        thread = self._threads.get(scan_id)
        return bool(thread and thread.is_alive() and scan_id in self._stop_events)

    def start_async(self, config: ScanConfig) -> str:
        t = threading.Thread(target=self.run, args=(config,), daemon=True, name=f"scan-{config.scan_id}")
        with self._lock:
            if config.worker_processes > 1:
                # Pre-register the multiprocessing stop event before the
                # thread starts, mirroring the threading.Event case below —
                # otherwise a stop() call racing with thread startup could
                # find neither bookkeeping dict populated yet and be lost.
                self._process_stop_events[config.scan_id] = multiprocessing.get_context("spawn").Event()
                self._processes[config.scan_id] = []
            else:
                self._stop_events[config.scan_id] = threading.Event()
            self._threads[config.scan_id] = t
        t.start()
        return config.scan_id

    def run(self, config: ScanConfig) -> dict[str, Any]:
        if config.worker_processes > 1:
            return self._run_multiprocess(config)
        scan_id = config.scan_id
        out_dir = Path(config.output_dir) / scan_id
        out_dir.mkdir(parents=True, exist_ok=True)
        stop_event = self._stop_events.get(scan_id) or threading.Event()
        self._stop_events[scan_id] = stop_event

        progress = ProgressManager(enable_cli=self.enable_cli_progress)
        http = HttpClient(
            timeout=config.timeout,
            connect_timeout=config.connect_timeout,
            retries=config.retries,
            verify_tls=config.verify_tls,
            proxy=config.proxy,
            headers=config.headers,
            max_body_bytes=config.max_body_bytes,
            rate_limit_per_host=max(float(getattr(config, "rate_limit_per_host", 50.0) or 50.0), 1.0),
            on_request=progress.record_request,
            # Give every worker thread a real chance at a free connection
            # instead of queuing behind a fixed-size pool.
            max_connections=max(512, int(config.threads) * 2),
        )
        with self._lock:
            self._clients[scan_id] = http
        logger = get_scan_logger(scan_id, out_dir, module="engine", level="DEBUG" if config.verbose else "INFO")

        def _log_cb(event: dict) -> None:
            if event.get("scan_id") != scan_id:
                return
            try:
                self.store.add_log(scan_id, event)
            except Exception:
                pass
            if self.on_log:
                try:
                    self.on_log(scan_id, event)
                except Exception:
                    pass

        add_log_subscriber(_log_cb)

        # Progress ticks fire on every request. Persist/broadcast at most a few
        # times per second so SQLite + the asyncio loop stay free for dashboard
        # API calls (otherwise the UI shows "Failed to fetch" / frozen jobs).
        last_prog_persist = {"t": 0.0}

        def _prog_cb(snap) -> None:
            now = time.monotonic()
            force = bool(getattr(snap, "percent", 0) >= 100 or stop_event.is_set())
            if not force and (now - last_prog_persist["t"]) < 0.5:
                return
            last_prog_persist["t"] = now
            data = asdict(snap)
            try:
                self.store.update_progress(scan_id, data)
            except Exception:
                pass
            if self.on_progress:
                try:
                    self.on_progress(scan_id, data)
                except Exception:
                    pass

        progress.subscribe(_prog_cb)

        # Keep the huge target/path arrays on disk only. Persisting them inside
        # config_json makes every Jobs poll parse ~175KB+ per scan and holds the
        # SQLite write lock long enough for dashboard fetch() calls to fail.
        if not config.targets_path:
            (out_dir / "targets.txt").write_text(
                "\n".join(config.targets) + ("\n" if config.targets else ""),
                encoding="utf-8",
            )
        if config.custom_paths and not config.wordlist_path:
            (out_dir / "custom_paths.txt").write_text(
                "\n".join(config.custom_paths) + "\n",
                encoding="utf-8",
            )
        cfg_dict = asdict(config)
        inline_targets = cfg_dict.pop("targets", []) or []
        inline_paths = cfg_dict.pop("custom_paths", []) or []
        cfg_dict.pop("targets_path", None)
        cfg_dict.pop("wordlist_path", None)
        cfg_dict["target_count"] = config.target_count or len(inline_targets)
        cfg_dict["custom_path_count"] = config.custom_path_count or len(inline_paths)
        self.store.create_scan(scan_id, cfg_dict, str(out_dir))
        self.store.update_status(scan_id, "stopping" if stop_event.is_set() else "running")
        logger.info(
            "scan start id=%s targets=%d threads=%d",
            scan_id,
            config.target_count or len(config.targets),
            config.threads,
        )

        persisted_ids: set[str] = set()

        def _live_finding(finding: Finding) -> None:
            self._persist_findings_live(scan_id, [finding], out_dir, persisted_ids)

        ctx = ScanContext(
            config=config,
            output_dir=out_dir,
            stop_event=stop_event,
            progress=progress,
            store=self.store,
            http=http,
            logger=logger,
        )

        try:
            target_count = config.target_count or len(config.targets)
            logger.info("streaming targets=%d", target_count)
            # Host-level progress: one Done unit = one domain/IP fully finished.
            progress.start(max(int(target_count), 1))
            if config.wordlist_path:
                config.custom_paths = list(dict.fromkeys([
                    *config.custom_paths,
                    *load_wordlist(config.wordlist_path),
                ]))
            modules = self._build_modules(config)
            pool = ThreadPoolExecutor(max_workers=max(1, config.threads))
            with self._lock:
                self._executors.setdefault(scan_id, []).append(pool)
            try:
                # Keep only a small window of futures. A 500MB target file can
                # contain millions of lines; submitting them all freezes/OOMs.
                max_inflight = max(config.threads * 3, config.threads)
                self._drain_pipeline(
                    targets=iter(self._ingest_targets(config)),
                    modules=modules,
                    ctx=ctx,
                    pool=pool,
                    max_inflight=max_inflight,
                    stop_event=stop_event,
                    on_finding=_live_finding,
                    on_target_done=lambda findings: self._persist_findings_live(
                        scan_id, findings, out_dir, persisted_ids
                    ),
                    logger=logger,
                )
            finally:
                pool.shutdown(wait=not stop_event.is_set(), cancel_futures=stop_event.is_set())
                with self._lock:
                    if pool in self._executors.get(scan_id, []):
                        self._executors[scan_id].remove(pool)

            findings_dicts = dedupe_findings(self.store.get_findings(scan_id))
            # Persist any leftovers not already streamed (dedupe / race edge).
            for fd in findings_dicts:
                fid = fd.get("id") or ""
                if fid and fid in persisted_ids:
                    continue
                self.store.add_finding(scan_id, fd)
                persisted_ids.add(fid)
                if self.on_finding:
                    try:
                        self.on_finding(scan_id, fd)
                    except Exception:
                        pass

            final_snap = progress.snapshot()
            try:
                self.store.update_progress(scan_id, asdict(final_snap))
            except Exception:
                pass
            report = self._write_reports(out_dir, config, findings_dicts, final_snap)
            status = "stopped" if stop_event.is_set() else "completed"
            self.store.update_status(scan_id, status)
            self.store.update_summary(scan_id, report.get("summary", {}))
            logger.info("scan %s findings=%d", status, len(findings_dicts))
            return report
        except Exception as e:
            logger.error("scan failed: %s", e)
            logger.debug(traceback.format_exc())
            self.store.update_status(scan_id, "failed")
            return {"error": str(e), "scan_id": scan_id}
        finally:
            progress.stop()
            remove_log_subscriber(_log_cb)
            http.close()
            with self._lock:
                self._stop_events.pop(scan_id, None)
                self._threads.pop(scan_id, None)
                self._executors.pop(scan_id, None)
                self._clients.pop(scan_id, None)
                self._last_artifact_write.pop(scan_id, None)

    def _run_multiprocess(self, config: ScanConfig) -> dict[str, Any]:
        """Fan a scan out across multiple OS processes.

        Each process gets its own GIL (the actual fix for the throughput
        ceiling measured with high thread counts in one process) and its own
        HttpClient/ProgressManager/ScanStore, built fresh via the spawn start
        method so nothing unsafe (live SQLAlchemy engine, background log
        writer thread, asyncio loop) is inherited across a fork(). Workers
        persist findings/logs/progress directly to the shared SQLite file
        (safe under WAL) and additionally relay lightweight copies through a
        queue purely so this process can keep pushing live websocket
        updates; losing that queue never loses data.
        """
        from app.core import process_worker  # local import: avoid a cycle at module load

        scan_id = config.scan_id
        out_dir = Path(config.output_dir) / scan_id
        out_dir.mkdir(parents=True, exist_ok=True)
        logger = get_scan_logger(scan_id, out_dir, module="engine", level="DEBUG" if config.verbose else "INFO")

        cpu_cap = os.cpu_count() or 4
        # Threads is per-process (UI: 300 threads + 3 processes => 300 each,
        # ~900 total concurrent targets). Dividing the thread budget across
        # processes was surprising and not what operators expect.
        num_workers = max(1, min(int(config.worker_processes), cpu_cap, 32))
        threads_per_process = max(1, min(SAFE_THREADS_PER_PROCESS, int(config.threads)))

        if not config.targets_path:
            (out_dir / "targets.txt").write_text(
                "\n".join(config.targets) + ("\n" if config.targets else ""),
                encoding="utf-8",
            )
        if config.custom_paths and not config.wordlist_path:
            (out_dir / "custom_paths.txt").write_text(
                "\n".join(config.custom_paths) + "\n",
                encoding="utf-8",
            )
        cfg_dict = asdict(config)
        inline_targets = cfg_dict.pop("targets", []) or []
        inline_paths = cfg_dict.pop("custom_paths", []) or []
        cfg_dict.pop("targets_path", None)
        cfg_dict.pop("wordlist_path", None)
        cfg_dict["target_count"] = config.target_count or len(inline_targets)
        cfg_dict["custom_path_count"] = config.custom_path_count or len(inline_paths)
        self.store.create_scan(scan_id, cfg_dict, str(out_dir))

        mp_ctx = multiprocessing.get_context("spawn")
        stop_event = self._process_stop_events.get(scan_id) or mp_ctx.Event()
        notify_queue: multiprocessing.Queue = mp_ctx.Queue()
        with self._lock:
            self._process_stop_events[scan_id] = stop_event
            self._processes[scan_id] = []
        self.store.update_status(scan_id, "stopping" if stop_event.is_set() else "running")

        target_count = config.target_count or len(config.targets)
        logger.info(
            "scan start id=%s targets=%d processes=%d threads_per_process=%d",
            scan_id, target_count, num_workers, threads_per_process,
        )

        processes: list[multiprocessing.Process] = []
        try:
            for worker_id in range(num_workers):
                p = mp_ctx.Process(
                    target=process_worker.run_worker,
                    args=(
                        config,
                        worker_id,
                        num_workers,
                        threads_per_process,
                        str(self.store.db_path),
                        notify_queue,
                        stop_event,
                    ),
                    daemon=True,
                    name=f"scan-{scan_id}-w{worker_id}",
                )
                p.start()
                processes.append(p)
            with self._lock:
                self._processes[scan_id] = processes

            aggregate = self._drain_multiprocess_queue(
                scan_id=scan_id,
                out_dir=out_dir,
                processes=processes,
                notify_queue=notify_queue,
                num_workers=num_workers,
                logger=logger,
            )

            findings_dicts = dedupe_findings(self.store.get_findings(scan_id))
            vuln_hosts = {
                (urlparse(str(f.get("target") or f.get("url") or "")).netloc or "").lower()
                for f in findings_dicts
            }
            vuln_hosts.discard("")
            final_snap_dict = {
                "total": aggregate.get("total", 0),
                "done": aggregate.get("done", 0),
                "failed": aggregate.get("failed", 0),
                "queued": max(aggregate.get("total", 0) - aggregate.get("done", 0) - aggregate.get("failed", 0), 0),
                "hits": len(findings_dicts),
                "vulnerable_hosts": len(vuln_hosts) or int(aggregate.get("vulnerable_hosts", 0) or 0),
                "secrets": aggregate.get("secrets", 0),
                "timeouts": aggregate.get("timeouts", 0),
                "requests": aggregate.get("requests", 0),
                "rps": aggregate.get("rps", 0.0),
                "current_target": "",
                "current_module": "",
                "percent": 100.0 if not stop_event.is_set() else float(aggregate.get("percent") or 0.0),
                "eta_seconds": 0.0,
                "module_progress": {},
            }
            report = self._write_reports(out_dir, config, findings_dicts, ProgressSnapshot(**final_snap_dict))
            status = "stopped" if stop_event.is_set() else "completed"
            self.store.update_status(scan_id, status)
            self.store.update_summary(scan_id, report.get("summary", {}))
            self.store.update_progress(scan_id, final_snap_dict)
            logger.info("scan %s findings=%d", status, len(findings_dicts))
            return report
        except Exception as e:
            logger.error("scan failed: %s", e)
            logger.debug(traceback.format_exc())
            self.store.update_status(scan_id, "failed")
            return {"error": str(e), "scan_id": scan_id}
        finally:
            stop_event.set()
            for p in processes:
                if p.is_alive():
                    p.join(timeout=5.0)
                if p.is_alive():
                    p.terminate()
            with self._lock:
                self._process_stop_events.pop(scan_id, None)
                self._processes.pop(scan_id, None)

    def _drain_multiprocess_queue(
        self,
        scan_id: str,
        out_dir: Path,
        processes: list[multiprocessing.Process],
        notify_queue: multiprocessing.Queue,
        num_workers: int,
        logger,
    ) -> dict[str, Any]:
        """Relay worker events to the dashboard and return the final
        aggregated progress snapshot once every worker process has exited."""
        worker_snapshots: dict[int, dict[str, Any]] = {}
        last_persist = {"t": 0.0}
        start_time = time.monotonic()
        # Artifact rebuilds can take tens of seconds once vulns/ grows large.
        # Never do that on this thread — it must keep draining the notify
        # queue or worker progress (Done/RPS) freezes on the dashboard.
        pending_artifact_refresh = {"dirty": False, "t": 0.0}
        artifact_thread: dict[str, Optional[threading.Thread]] = {"t": None}
        artifact_lock = threading.Lock()

        def _aggregate() -> dict[str, Any]:
            snaps = list(worker_snapshots.values())
            agg = {
                "total": sum(s.get("total", 0) for s in snaps),
                "done": sum(s.get("done", 0) for s in snaps),
                "failed": sum(s.get("failed", 0) for s in snaps),
                "hits": sum(s.get("hits", 0) for s in snaps),
                "vulnerable_hosts": sum(s.get("vulnerable_hosts", 0) for s in snaps),
                "secrets": sum(s.get("secrets", 0) for s in snaps),
                "timeouts": sum(s.get("timeouts", 0) for s in snaps),
                "requests": sum(s.get("requests", 0) for s in snaps),
                "rps": sum(s.get("rps", 0.0) for s in snaps),
            }
            finished = agg["done"] + agg["failed"]
            agg["queued"] = max(agg["total"] - finished, 0)
            agg["percent"] = (finished / agg["total"] * 100.0) if agg["total"] else 0.0
            agg["current_target"] = next((s.get("current_target", "") for s in snaps if s.get("current_target")), "")
            agg["current_module"] = next((s.get("current_module", "") for s in snaps if s.get("current_module")), "")
            elapsed = max(time.monotonic() - start_time, 0.001)
            rate = finished / elapsed
            remaining = max(agg["total"] - finished, 0)
            agg["eta_seconds"] = (remaining / rate) if rate > 0 else None
            module_progress: dict[str, dict[str, int]] = {}
            for snap in snaps:
                for name, mp in (snap.get("module_progress") or {}).items():
                    entry = module_progress.setdefault(name, {"done": 0, "total": 0, "hits": 0})
                    entry["done"] += mp.get("done", 0)
                    entry["total"] += mp.get("total", 0)
                    entry["hits"] += mp.get("hits", 0)
            agg["module_progress"] = module_progress
            return agg

        def _persist_aggregate(force: bool = False) -> dict[str, Any]:
            agg = _aggregate()
            now = time.monotonic()
            if force or (now - last_persist["t"]) >= 0.5:
                last_persist["t"] = now
                try:
                    self.store.update_progress(scan_id, agg)
                except Exception:
                    pass
                if self.on_progress:
                    try:
                        self.on_progress(scan_id, agg)
                    except Exception:
                        pass
            return agg

        while True:
            try:
                message = notify_queue.get(timeout=0.5)
            except queue_mod.Empty:
                message = None
            except Exception:
                message = None

            if message is not None:
                mtype = message.get("type")
                if mtype == "log":
                    try:
                        if self.on_log:
                            self.on_log(scan_id, message.get("data") or {})
                    except Exception:
                        pass
                elif mtype == "finding":
                    try:
                        if self.on_finding:
                            self.on_finding(scan_id, message.get("data") or {})
                    except Exception:
                        pass
                    pending_artifact_refresh["dirty"] = True
                elif mtype == "worker_progress":
                    worker_snapshots[message.get("worker_id")] = message.get("data") or {}
                    _persist_aggregate()

            # Findings arrive from up to num_workers processes concurrently.
            # Rebuild vulns/ off-thread and infrequently so the notify drain
            # (live Done/RPS) never blocks behind a multi-minute rmtree+rewrite.
            now = time.monotonic()
            existing_art = artifact_thread["t"]
            art_busy = bool(existing_art and existing_art.is_alive())
            if (
                pending_artifact_refresh["dirty"]
                and not art_busy
                and (now - pending_artifact_refresh["t"]) >= 30.0
            ):
                pending_artifact_refresh["dirty"] = False
                pending_artifact_refresh["t"] = now

                def _refresh_artifacts() -> None:
                    with artifact_lock:
                        try:
                            write_vuln_artifacts(out_dir, self.store.get_findings(scan_id))
                        except Exception:
                            pass

                t = threading.Thread(
                    target=_refresh_artifacts,
                    daemon=True,
                    name=f"vulns-{scan_id[:8]}",
                )
                artifact_thread["t"] = t
                t.start()

            if not any(p.is_alive() for p in processes):
                # Drain whatever is left in the queue without blocking forever.
                deadline = time.monotonic() + 2.0
                while time.monotonic() < deadline:
                    try:
                        message = notify_queue.get(timeout=0.1)
                    except Exception:
                        break
                    if message and message.get("type") == "worker_progress":
                        worker_snapshots[message.get("worker_id")] = message.get("data") or {}
                break

        art = artifact_thread["t"]
        if art is not None and art.is_alive():
            art.join(timeout=10.0)
        return _persist_aggregate(force=True)

    def _ingest_targets(self, config: ScanConfig) -> Iterator[str]:
        """Yield normalized targets lazily; memory stays flat for huge uploads."""
        for target in config.targets:
            normalized = normalize_target((target or "").strip())
            if normalized:
                yield normalized
        if config.targets_path:
            for target in iter_target_lines(config.targets_path):
                normalized = normalize_target(target)
                if normalized:
                    yield normalized

    def _drain_pipeline(
        self,
        targets: Iterator[str],
        modules: list[Any],
        ctx: ScanContext,
        pool: ThreadPoolExecutor,
        max_inflight: int,
        stop_event: Any,
        on_finding: Optional[Callable[[Finding], None]],
        on_target_done: Callable[[list[Finding]], None],
        logger,
    ) -> None:
        """Feed a bounded window of targets through the pipeline pool.

        Shared by the single-process run() loop and each multi-process
        worker, so both modes exercise exactly the same submission/backoff
        logic instead of two copies that could silently drift apart.
        """
        inflight: dict[Future, str] = {}
        exhausted = False
        while (inflight or not exhausted) and not stop_event.is_set():
            while len(inflight) < max_inflight and not exhausted and not stop_event.is_set():
                try:
                    turl = next(targets)
                except StopIteration:
                    exhausted = True
                    break
                future = pool.submit(self._run_target_pipeline, turl, modules, ctx, on_finding, logger)
                inflight[future] = turl
            if not inflight:
                continue
            # Timed wait so a Stop request is not blocked behind a single
            # slow/hung target (which previously kept workers alive and their
            # RSS pinned for the full HTTP timeout window).
            done, _ = wait(inflight, timeout=0.5, return_when=FIRST_COMPLETED)
            if stop_event.is_set():
                for fut in list(inflight):
                    fut.cancel()
                break
            for future in done:
                turl = inflight.pop(future)
                try:
                    on_target_done(future.result())
                except Exception as e:
                    # ``_run_target_pipeline`` already counted this host via
                    # ``complete_target`` before re-raising.
                    logger.error("target failed %s: %s", turl, e)
                    logger.debug(traceback.format_exc())

    def _run_target_pipeline(
        self,
        turl: str,
        modules: list[Any],
        ctx: ScanContext,
        on_finding: Optional[Callable[[Finding], None]],
        logger,
    ) -> list[Finding]:
        findings: list[Finding] = []
        completed = False
        try:
            for target in self._prepare_target(
                ctx.http,
                turl,
                ctx.config,
                ctx.progress,
                logger,
            ):
                if ctx.stop_event.is_set():
                    break
                findings.extend(self._scan_target(target, modules, ctx, on_finding))
            if findings:
                ctx.progress.note_vulnerable_host(turl)
                for finding in findings:
                    host = getattr(finding, "target", None) or getattr(finding, "url", None) or turl
                    ctx.progress.note_vulnerable_host(str(host))
            ctx.progress.complete_target(success=True)
            completed = True
            return findings
        except Exception:
            if not completed:
                ctx.progress.complete_target(success=False)
            raise

    def _prepare_target(
        self,
        http: HttpClient,
        turl: str,
        config: ScanConfig,
        progress: ProgressManager,
        logger,
    ) -> list[TargetContext]:
        progress.set_current(target=turl, module="probe")
        chosen = self._live_probes(http, turl, config.probe_both_schemes)
        progress.tick(success=bool(chosen), timeout=False, module="probe")
        if not chosen:
            # Fires per dead target — DEBUG only, since bug-bounty target
            # lists commonly contain millions of unreachable hosts and this
            # was, by far, the largest source of log volume at scale.
            logger.debug("target offline/unreachable: %s", turl)
            return []
        for target in chosen:
            try:
                profile = http.build_soft404_profile(target.url)
                target.soft404_profile = profile
                logger.debug("soft404 profile host=%s status=%s", target.url, profile.get("status"))
            except Exception as e:
                logger.warning("soft404 failed: %s", e)
            progress.set_current(target=target.url, module="fingerprint")
            fp = fingerprint_target(http, target.url)
            target.tech = fp.get("tech", [])
            target.title = fp.get("title", "")
            target.status_code = fp.get("status_code", target.status_code)
            target.final_url = fp.get("final_url", target.url)
            target.headers = fp.get("headers", {})
            target.meta = fp.get("meta", {})
            progress.tick(success=True, module="fingerprint")
            logger.debug("fingerprint %s -> %s", target.url, ",".join(target.tech) or "generic")
        return chosen

    def _live_probe(self, http: HttpClient, url: str, both: bool) -> TargetContext:
        """Backward-compatible first live origin; prefer the input scheme."""
        live = self._live_probes(http, url, both)
        return live[0] if live else TargetContext(url=normalize_target(url), live=False)

    def _live_probes(self, http: HttpClient, url: str, both: bool) -> list[TargetContext]:
        """Return every distinct live HTTP/HTTPS origin for this target."""
        candidates = origin_variants(url) if both else [normalize_target(url)]
        live: list[TargetContext] = []
        seen: set[str] = set()
        for cand in candidates:
            resp = http.probe_live(cand)
            ctx = TargetContext(
                url=normalize_target(resp.url or cand),
                live=resp.status_code > 0 and not resp.error,
                final_url=resp.url or cand,
                status_code=resp.status_code,
                headers=resp.headers,
            )
            # Redirected HTTP -> HTTPS is the same effective origin; scan once.
            if ctx.live and ctx.url not in seen:
                seen.add(ctx.url)
                live.append(ctx)
        return live

    def _build_modules(self, config: ScanConfig) -> list[Any]:
        enabled = set(config.modules)
        mods: list[Any] = []
        if "git" in enabled:
            mods.append(GitExposureModule())
        if "js" in enabled or "crawl" in enabled:
            mods.append(JsSecretsModule())
        if "config" in enabled:
            mods.append(ConfigEnvModule(extra_paths=config.custom_paths if config.paths_mode == "merge" else None))
        if "path" in enabled:
            mods.append(PathBruteforceModule(custom_paths=config.custom_paths, mode=config.paths_mode))
        if "methods" in enabled:
            mods.append(MethodTesterModule())
        if "wordpress" in enabled or "wp" in enabled:
            mods.append(WordPressModule())
        if "joomla" in enabled:
            mods.append(JoomlaModule())
        if "react" in enabled or "react2shell" in enabled:
            mods.append(ReactModule())
        # custom paths only mode still need path module
        if config.custom_paths and "path" not in enabled and config.paths_mode == "custom_only":
            mods.append(PathBruteforceModule(custom_paths=config.custom_paths, mode="custom_only"))
        return mods

    def _persist_findings_live(
        self,
        scan_id: str,
        findings: list[Finding],
        out_dir: Path,
        persisted_ids: set[str],
    ) -> None:
        if not findings:
            return
        batch = []
        with self._lock:
            for finding in findings:
                fd = finding.to_dict()
                fid = fd.get("id") or ""
                if not fid or fid in persisted_ids:
                    continue
                persisted_ids.add(fid)
                batch.append(fd)
        for fd in batch:
            try:
                self.store.add_finding(scan_id, fd)
            except Exception:
                pass
            if self.on_finding:
                try:
                    self.on_finding(scan_id, fd)
                except Exception:
                    pass
        if not batch:
            return
        # Serialize artifact writes across worker threads. Rebuild the heavier
        # vuln tree at most every two seconds; SQLite and WebSocket are immediate.
        with self._artifact_lock:
            hits_path = Path(out_dir) / "hits.jsonl"
            with hits_path.open("a", encoding="utf-8") as fh:
                for fd in batch:
                    fh.write(json.dumps(fd, ensure_ascii=False) + "\n")
            now = time.monotonic()
            if now - self._last_artifact_write.get(scan_id, 0.0) >= 2.0:
                try:
                    existing = self.store.get_findings(scan_id)
                    write_vuln_artifacts(out_dir, existing)
                    self._last_artifact_write[scan_id] = now
                except Exception:
                    pass

    def _scan_target(
        self,
        target: TargetContext,
        modules: list[Any],
        ctx: ScanContext,
        on_finding: Optional[Callable[[Finding], None]] = None,
    ) -> list[Finding]:
        # per-target shallow copy of mutable lists to avoid cross-talk; findings go to local then merge
        local_ctx = ScanContext(
            config=ctx.config,
            output_dir=ctx.output_dir,
            stop_event=ctx.stop_event,
            progress=ctx.progress,
            store=ctx.store,
            http=ctx.http,
            logger=ctx.logger,
            findings=[],
            bodies=[],
        )
        out: list[Finding] = []
        log = get_scan_logger(ctx.config.scan_id, ctx.output_dir, module="engine")
        # DEBUG only: these fire per target (and per module below), which at
        # 10M+ targets is the single largest source of log volume/DB writes.
        log.debug("target start %s tech=%s", target.url, ",".join(target.tech))
        # Shuffle per host so heavy modules (path) do not always starve
        # wordpress / joomla / react on every target.
        ordered = list(modules)
        random.shuffle(ordered)

        def _on_finding_wrapped(finding: Finding) -> None:
            try:
                ctx.progress.note_vulnerable_host(
                    getattr(finding, "target", "") or getattr(finding, "url", "") or target.url
                )
            except Exception:
                pass
            if on_finding:
                on_finding(finding)

        for mod in ordered:
            if ctx.stop_event.is_set():
                break
            name = getattr(mod, "name", mod.__class__.__name__)
            if hasattr(mod, "match") and not mod.match(target):
                continue
            ctx.progress.set_current(target=target.url, module=name)
            mlog = get_scan_logger(ctx.config.scan_id, ctx.output_dir, module=name)
            local_ctx.logger = mlog
            mlog.debug("module start on %s", target.url)
            try:
                with stream_findings(_on_finding_wrapped):
                    findings = mod.run(target, local_ctx) or []
                out.extend(findings)
                # share findings for later modules (method tester uses endpoints)
                local_ctx.findings.extend(findings)
                if findings:
                    ctx.progress.note_vulnerable_host(target.url)
                mlog.debug("module end hits=%d", len(findings))
            except Exception as e:
                mlog.error("module error: %s", e)
                mlog.debug(traceback.format_exc())
        log.debug("target end %s findings=%d", target.url, len(out))
        return out

    def _write_reports(self, out_dir: Path, config: ScanConfig, findings: list[dict], snap) -> dict[str, Any]:
        summary = {
            "scan_id": config.scan_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            # Persist counts only — full target arrays bloat Jobs API polls.
            "target_count": config.target_count or len(config.targets),
            "modules": config.modules,
            "finding_count": len(findings),
            "by_severity": {},
            "progress": asdict(snap) if hasattr(snap, "__dataclass_fields__") else {},
        }
        for f in findings:
            sev = f.get("severity", "info")
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

        report_config = asdict(config)
        report_config.pop("targets", None)
        report_config.pop("custom_paths", None)
        report_config.pop("targets_path", None)
        report_config.pop("wordlist_path", None)
        report_config["target_count"] = config.target_count or len(config.targets)
        report_config["custom_path_count"] = config.custom_path_count or len(config.custom_paths)
        report = {
            "summary": summary,
            "findings": findings,
            "config": report_config,
        }
        if "json" in config.formats:
            (out_dir / "report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        if "md" in config.formats:
            (out_dir / "report.md").write_text(self._to_markdown(report), encoding="utf-8")
        if "csv" in config.formats:
            with (out_dir / "findings.csv").open("w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(
                    f,
                    fieldnames=[
                        "id", "type", "severity", "target", "url", "title",
                        "confidence", "module", "validated", "evidence",
                    ],
                )
                w.writeheader()
                for item in findings:
                    w.writerow({k: item.get(k, "") for k in w.fieldnames})
        vuln_bundle = write_vuln_artifacts(out_dir, findings)
        summary["vulnerable_host_count"] = vuln_bundle.get("summary", {}).get("vulnerable_host_count", 0)
        summary["vuln_finding_count"] = vuln_bundle.get("summary", {}).get("vuln_finding_count", 0)
        summary["vuln_dir"] = vuln_bundle.get("dir", "")
        report["vulnerable_hosts"] = vuln_bundle.get("vulnerable_hosts", [])
        report["vulns"] = vuln_bundle.get("summary", {})
        return report

    @staticmethod
    def _to_markdown(report: dict[str, Any]) -> str:
        s = report["summary"]
        lines = [
            f"# Scan Report `{s['scan_id']}`",
            "",
            f"- Generated: {s['generated_at']}",
            f"- Findings: {s['finding_count']}",
            f"- Severity: {json.dumps(s.get('by_severity', {}))}",
            "",
            "## Findings",
            "",
        ]
        for f in report.get("findings", []):
            lines.extend(
                [
                    f"### [{f.get('severity','').upper()}] {f.get('title')}",
                    f"- Type: `{f.get('type')}` | Module: `{f.get('module')}` | Confidence: `{f.get('confidence')}`",
                    f"- URL: {f.get('url')}",
                    f"- Evidence: `{str(f.get('evidence',''))[:200]}`",
                    f"- Reproduction: `curl -i '{f.get('url')}'`",
                    "",
                ]
            )
        return "\n".join(lines)