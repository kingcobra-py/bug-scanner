"""Custom + common sensitive path bruteforce."""

from __future__ import annotations

from app.core.wordlists import load_wordlist, WORDLIST_DIR, merge_paths
from app.modules.base import body_extractions, finding_from_hit, save_evidence
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url


class PathBruteforceModule:
    name = "path"

    def __init__(self, custom_paths: list[str] | None = None, mode: str = "merge") -> None:
        self.paths = merge_paths(
            custom=custom_paths or [],
            mode=mode if mode in ("merge", "custom_only", "builtin_only") else "merge",
            builtin_kinds=["common"],
        )

    def match(self, target: TargetContext) -> bool:
        return bool(target.live)

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        http = ctx.http
        # Avoid re-testing pure git/config/js lists already covered; keep common + custom
        paths = self.paths
        ctx.progress.module_set_total(self.name, len(paths))
        for path in paths:
            if ctx.stop_event.is_set():
                break
            url = path if path.startswith("http") else join_url(target.url, path)
            resp = http.get(url)
            timed_out = bool(resp.error and "timeout" in resp.error)
            ctx.progress.tick(success=not bool(resp.error), timeout=timed_out, module=self.name)
            if resp.error or resp.soft404:
                continue
            if resp.status_code in (200, 401, 403):
                interesting = resp.status_code in (401, 403) or len(resp.content) > 0
                if not interesting:
                    continue
                extracted = body_extractions(ctx, resp.url or url, resp.text or "")
                has_signal = bool(extracted.get("secrets") or extracted.get("smtp") or extracted.get("apis"))
                # high-value path names always report
                low = path.lower()
                high_value = any(
                    x in low
                    for x in (
                        "admin", "backup", "phpinfo", "swagger", "graphql", "actuator",
                        "wp-config", "id_rsa", ".sql", "debug.log", "server-status",
                    )
                )
                if not (has_signal or high_value or resp.status_code in (401, 403)):
                    continue
                raw_ref = ""
                if resp.status_code == 200 and resp.text:
                    raw_ref = save_evidence(ctx, f"path_{path}", resp.text)
                sev = "high" if has_signal or "backup" in low or "wp-config" in low else "medium"
                if resp.status_code in (401, 403) and not has_signal:
                    sev = "info"
                f = finding_from_hit(
                    module=self.name,
                    ftype="path",
                    severity=sev,
                    target=target,
                    url=resp.url or url,
                    title=f"Interesting path {path} [{resp.status_code}]",
                    evidence=(resp.text or "")[:240] or f"status={resp.status_code}",
                    confidence=0.8 if has_signal else 0.55,
                    extracted=extracted,
                    raw_ref=raw_ref,
                    tags=["path"],
                )
                findings.append(f)
                ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
        return findings