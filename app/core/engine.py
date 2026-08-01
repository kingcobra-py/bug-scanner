"""Thread-based scan orchestrator."""

from __future__ import annotations

import csv
import json
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from app.core.fingerprint import fingerprint_target
from app.core.http_client import HttpClient
from app.core.progress import ProgressManager
from app.core.vuln_artifacts import write_vuln_artifacts
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
from app.storage.models import Finding, ScanConfig, ScanContext, TargetContext
from app.utils.dedupe import dedupe_findings, dedupe_strings
from app.utils.logger import get_scan_logger, add_log_subscriber, remove_log_subscriber
from app.utils.normalize import normalize_target, origin_variants


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

    def stop(self, scan_id: str) -> bool:
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
        thread = self._threads.get(scan_id)
        return bool(thread and thread.is_alive() and scan_id in self._stop_events)

    def start_async(self, config: ScanConfig) -> str:
        t = threading.Thread(target=self.run, args=(config,), daemon=True, name=f"scan-{config.scan_id}")
        with self._lock:
            self._stop_events[config.scan_id] = threading.Event()
            self._threads[config.scan_id] = t
        t.start()
        return config.scan_id

    def run(self, config: ScanConfig) -> dict[str, Any]:
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
        (out_dir / "targets.txt").write_text(
            "\n".join(config.targets) + ("\n" if config.targets else ""),
            encoding="utf-8",
        )
        if config.custom_paths:
            (out_dir / "custom_paths.txt").write_text(
                "\n".join(config.custom_paths) + "\n",
                encoding="utf-8",
            )
        cfg_dict = asdict(config)
        cfg_dict["target_count"] = len(cfg_dict.pop("targets", []) or [])
        cfg_dict["custom_path_count"] = len(cfg_dict.pop("custom_paths", []) or [])
        self.store.create_scan(scan_id, cfg_dict, str(out_dir))
        self.store.update_status(scan_id, "stopping" if stop_event.is_set() else "running")
        logger.info("scan start id=%s targets=%d threads=%d", scan_id, len(config.targets), config.threads)

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
            targets = self._ingest_targets(config)
            logger.info("normalized targets=%d", len(targets))
            # estimate tasks loosely
            est = max(len(targets) * max(len(config.modules), 1) * 10, 1)
            progress.start(est)

            live_targets: list[TargetContext] = []
            probe_workers = max(1, min(int(config.threads), len(targets) or 1))
            logger.info(
                "probe phase workers=%d rate_limit_per_host=%.1f",
                probe_workers,
                float(getattr(config, "rate_limit_per_host", 50.0) or 50.0),
            )
            probe_pool = ThreadPoolExecutor(max_workers=probe_workers)
            with self._lock:
                self._executors.setdefault(scan_id, []).append(probe_pool)
            try:
                futs = {
                    probe_pool.submit(self._prepare_target, http, turl, config, progress, logger): turl
                    for turl in targets
                }
                for fut in as_completed(futs):
                    if stop_event.is_set():
                        break
                    turl = futs[fut]
                    try:
                        chosen = fut.result()
                    except Exception as e:
                        logger.error("probe failed %s: %s", turl, e)
                        progress.tick(success=False, module="probe")
                        continue
                    if not chosen or not chosen.live:
                        continue
                    live_targets.append(chosen)
            finally:
                probe_pool.shutdown(wait=not stop_event.is_set(), cancel_futures=stop_event.is_set())
                with self._lock:
                    if probe_pool in self._executors.get(scan_id, []):
                        self._executors[scan_id].remove(probe_pool)

            modules = self._build_modules(config)
            # refine total
            progress.set_total(max(len(live_targets) * len(modules) * 8, progress.snapshot().total))

            all_findings: list[Finding] = []
            pool = ThreadPoolExecutor(max_workers=max(1, config.threads))
            with self._lock:
                self._executors.setdefault(scan_id, []).append(pool)
            try:
                # Target-level parallelism; persist/broadcast findings as each target finishes.
                futs = {
                    pool.submit(self._scan_target, tgt, modules, ctx, _live_finding): tgt
                    for tgt in live_targets
                }
                for fut in as_completed(futs):
                    if stop_event.is_set():
                        break
                    tgt = futs[fut]
                    try:
                        findings = fut.result()
                        all_findings.extend(findings)
                        self._persist_findings_live(
                            scan_id,
                            findings,
                            out_dir,
                            persisted_ids,
                        )
                    except Exception as e:
                        logger.error("target failed %s: %s", tgt.url, e)
                        logger.debug(traceback.format_exc())
            finally:
                pool.shutdown(wait=not stop_event.is_set(), cancel_futures=stop_event.is_set())
                with self._lock:
                    if pool in self._executors.get(scan_id, []):
                        self._executors[scan_id].remove(pool)

            # global extraction pass on collected bodies
            progress.set_current(module="extract")
            for url, body in list(ctx.bodies):
                if stop_event.is_set():
                    break
                # already extracted in modules; skip heavy rework
                progress.tick(success=True, module="extract")

            findings_dicts = dedupe_findings([f.to_dict() for f in all_findings + ctx.findings])
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

    def _ingest_targets(self, config: ScanConfig) -> list[str]:
        raw = []
        for t in config.targets:
            t = (t or "").strip()
            if not t or t.startswith("#"):
                continue
            raw.append(normalize_target(t))
        return dedupe_strings([t for t in raw if t])

    def _prepare_target(
        self,
        http: HttpClient,
        turl: str,
        config: ScanConfig,
        progress: ProgressManager,
        logger,
    ) -> Optional[TargetContext]:
        progress.set_current(target=turl, module="probe")
        chosen = self._live_probe(http, turl, config.probe_both_schemes)
        progress.tick(success=chosen.live, timeout=False, module="probe")
        if not chosen.live:
            logger.warning("target offline/unreachable: %s", turl)
            return None
        try:
            profile = http.build_soft404_profile(chosen.url)
            chosen.soft404_profile = profile
            logger.info("soft404 profile host=%s status=%s", chosen.url, profile.get("status"))
        except Exception as e:
            logger.warning("soft404 failed: %s", e)
        progress.set_current(target=chosen.url, module="fingerprint")
        fp = fingerprint_target(http, chosen.url)
        chosen.tech = fp.get("tech", [])
        chosen.title = fp.get("title", "")
        chosen.status_code = fp.get("status_code", chosen.status_code)
        chosen.final_url = fp.get("final_url", chosen.url)
        chosen.headers = fp.get("headers", {})
        chosen.meta = fp.get("meta", {})
        progress.tick(success=True, module="fingerprint")
        logger.info("fingerprint %s -> %s", chosen.url, ",".join(chosen.tech) or "generic")
        return chosen

    def _live_probe(self, http: HttpClient, url: str, both: bool) -> TargetContext:
        candidates = origin_variants(url) if both else [normalize_target(url)]
        best: Optional[TargetContext] = None
        for cand in candidates:
            resp = http.probe_live(cand)
            ctx = TargetContext(
                url=normalize_target(resp.url or cand),
                live=resp.status_code > 0 and not resp.error,
                final_url=resp.url or cand,
                status_code=resp.status_code,
                headers=resp.headers,
            )
            if ctx.live:
                # prefer https if both live
                if best is None or cand.startswith("https://"):
                    best = ctx
                    if cand.startswith("https://"):
                        break
        return best or TargetContext(url=normalize_target(url), live=False)

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
        log.info("target start %s tech=%s", target.url, ",".join(target.tech))
        for mod in modules:
            if ctx.stop_event.is_set():
                break
            name = getattr(mod, "name", mod.__class__.__name__)
            if hasattr(mod, "match") and not mod.match(target):
                continue
            ctx.progress.set_current(target=target.url, module=name)
            mlog = get_scan_logger(ctx.config.scan_id, ctx.output_dir, module=name)
            local_ctx.logger = mlog
            mlog.info("module start on %s", target.url)
            try:
                with stream_findings(on_finding):
                    findings = mod.run(target, local_ctx) or []
                out.extend(findings)
                # share findings for later modules (method tester uses endpoints)
                local_ctx.findings.extend(findings)
                mlog.info("module end hits=%d", len(findings))
            except Exception as e:
                mlog.error("module error: %s", e)
                mlog.debug(traceback.format_exc())
        # merge bodies for global extract
        with self._lock:
            ctx.bodies.extend(local_ctx.bodies)
            ctx.findings.extend(out)
        log.info("target end %s findings=%d", target.url, len(out))
        return out

    def _write_reports(self, out_dir: Path, config: ScanConfig, findings: list[dict], snap) -> dict[str, Any]:
        summary = {
            "scan_id": config.scan_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            # Persist counts only — full target arrays bloat Jobs API polls.
            "target_count": len(config.targets),
            "modules": config.modules,
            "finding_count": len(findings),
            "by_severity": {},
            "progress": asdict(snap) if hasattr(snap, "__dataclass_fields__") else {},
        }
        for f in findings:
            sev = f.get("severity", "info")
            summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1

        report = {
            "summary": summary,
            "findings": findings,
            "config": asdict(config),
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