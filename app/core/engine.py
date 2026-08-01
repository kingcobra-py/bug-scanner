"""Thread-based scan orchestrator."""

from __future__ import annotations

import csv
import json
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from app.core.fingerprint import fingerprint_target
from app.core.http_client import HttpClient
from app.core.progress import ProgressManager
from app.modules.config_env import ConfigEnvModule
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
        self._lock = threading.Lock()

    def stop(self, scan_id: str) -> bool:
        ev = self._stop_events.get(scan_id)
        if not ev:
            return False
        ev.set()
        self.store.update_status(scan_id, "stopping")
        return True

    def start_async(self, config: ScanConfig) -> str:
        t = threading.Thread(target=self.run, args=(config,), daemon=True, name=f"scan-{config.scan_id}")
        with self._lock:
            self._threads[config.scan_id] = t
        t.start()
        return config.scan_id

    def run(self, config: ScanConfig) -> dict[str, Any]:
        scan_id = config.scan_id
        out_dir = Path(config.output_dir) / scan_id
        out_dir.mkdir(parents=True, exist_ok=True)
        stop_event = threading.Event()
        self._stop_events[scan_id] = stop_event

        progress = ProgressManager(enable_cli=self.enable_cli_progress)
        http = HttpClient(
            timeout=config.timeout,
            connect_timeout=config.connect_timeout,
            retries=2,
            verify_tls=config.verify_tls,
            proxy=config.proxy,
            headers=config.headers,
            max_body_bytes=config.max_body_bytes,
        )
        logger = get_scan_logger(scan_id, out_dir, module="engine", level="DEBUG" if config.verbose else "INFO")

        def _log_cb(event: dict) -> None:
            if event.get("scan_id") not in (scan_id, "-"):
                # adapter always sets scan_id
                pass
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

        def _prog_cb(snap) -> None:
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

        cfg_dict = asdict(config)
        self.store.create_scan(scan_id, cfg_dict, str(out_dir))
        self.store.update_status(scan_id, "running")
        logger.info("scan start id=%s targets=%d threads=%d", scan_id, len(config.targets), config.threads)

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
            for turl in targets:
                if stop_event.is_set():
                    break
                progress.set_current(target=turl, module="probe")
                chosen = self._live_probe(http, turl, config.probe_both_schemes)
                progress.tick(success=chosen.live, timeout=False, module="probe")
                if not chosen.live:
                    logger.warning("target offline/unreachable: %s", turl)
                    continue
                # soft404 baseline
                try:
                    profile = http.build_soft404_profile(chosen.url)
                    chosen.soft404_profile = profile
                    logger.info("soft404 profile host=%s status=%s", chosen.url, profile.get("status"))
                except Exception as e:
                    logger.warning("soft404 failed: %s", e)
                # fingerprint
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
                live_targets.append(chosen)

            modules = self._build_modules(config)
            # refine total
            progress.set_total(max(len(live_targets) * len(modules) * 8, progress.snapshot().total))

            all_findings: list[Finding] = []
            with ThreadPoolExecutor(max_workers=max(1, config.threads)) as pool:
                # Process targets sequentially for clearer progress; modules can fan out internally via http threads.
                # Still use pool for target-level parallelism when many hosts.
                futs = {
                    pool.submit(self._scan_target, tgt, modules, ctx): tgt
                    for tgt in live_targets
                }
                for fut in as_completed(futs):
                    if stop_event.is_set():
                        break
                    tgt = futs[fut]
                    try:
                        findings = fut.result()
                        all_findings.extend(findings)
                    except Exception as e:
                        logger.error("target failed %s: %s", tgt.url, e)
                        logger.debug(traceback.format_exc())

            # global extraction pass on collected bodies
            progress.set_current(module="extract")
            for url, body in list(ctx.bodies):
                if stop_event.is_set():
                    break
                # already extracted in modules; skip heavy rework
                progress.tick(success=True, module="extract")

            findings_dicts = dedupe_findings([f.to_dict() for f in all_findings + ctx.findings])
            for fd in findings_dicts:
                self.store.add_finding(scan_id, fd)
                if self.on_finding:
                    try:
                        self.on_finding(scan_id, fd)
                    except Exception:
                        pass

            report = self._write_reports(out_dir, config, findings_dicts, progress.snapshot())
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
            self._stop_events.pop(scan_id, None)

    def _ingest_targets(self, config: ScanConfig) -> list[str]:
        raw = []
        for t in config.targets:
            t = (t or "").strip()
            if not t or t.startswith("#"):
                continue
            raw.append(normalize_target(t))
        return dedupe_strings([t for t in raw if t])

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

    def _scan_target(self, target: TargetContext, modules: list[Any], ctx: ScanContext) -> list[Finding]:
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
            "targets": config.targets,
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