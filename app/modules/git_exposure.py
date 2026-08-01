"""Git exposure discovery and light content extraction."""

from __future__ import annotations

from app.core.wordlists import load_wordlist, WORDLIST_DIR
from app.extractors.patterns import GIT_CONFIG, GIT_HEAD
from app.modules.base import body_extractions, finding_from_hit, save_evidence
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url


class GitExposureModule:
    name = "git"

    def __init__(self, extra_paths: list[str] | None = None) -> None:
        self.paths = load_wordlist(WORDLIST_DIR / "git.txt")
        if extra_paths:
            self.paths = list(dict.fromkeys([*self.paths, *extra_paths]))

    def match(self, target: TargetContext) -> bool:
        return bool(target.live)

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        log = ctx.logger
        http = ctx.http
        ctx.progress.module_set_total(self.name, len(self.paths))
        head_hit = None

        for path in self.paths:
            if ctx.stop_event.is_set():
                break
            url = path if path.startswith("http") else join_url(target.url, path)
            resp = http.get(url)
            timed_out = bool(resp.error and "timeout" in resp.error)
            ctx.progress.tick(success=not timed_out, timeout=timed_out, module=self.name)
            if resp.error or resp.soft404:
                continue
            interesting = False
            conf = 0.5
            title = f"Git path {path}"
            if path.endswith("HEAD") or path.endswith("/HEAD"):
                if resp.status_code == 200 and GIT_HEAD.search(resp.text or ""):
                    interesting = True
                    conf = 0.97
                    title = "Exposed .git/HEAD"
                    head_hit = resp
                elif resp.status_code == 403 and resp.forbidden_but_exists:
                    interesting = True
                    conf = 0.7
                    title = "Forbidden but present .git/HEAD"
            elif "config" in path and resp.status_code == 200 and GIT_CONFIG.search(resp.text or ""):
                interesting = True
                conf = 0.95
                title = "Exposed .git/config"
            elif resp.status_code == 200 and path.rstrip("/").endswith(".git"):
                if "directory listing" in (resp.text or "").lower() or "HEAD" in (resp.text or ""):
                    interesting = True
                    conf = 0.85
                    title = "Open git directory listing"
            elif resp.status_code == 200 and ("/.git/" in path or path.endswith(".git/index")):
                # binary index or logs with content
                if len(resp.content) > 20:
                    interesting = True
                    conf = 0.8
                    title = f"Exposed git artifact {path}"
            elif resp.status_code == 403 and resp.forbidden_but_exists and "/.git" in path:
                interesting = True
                conf = 0.6
                title = f"Git path forbidden-but-exists {path}"

            if not interesting:
                continue

            raw_ref = save_evidence(ctx, f"git_{path}", resp.content if resp.content else resp.text, ext="bin" if path.endswith("index") else "txt")
            extracted = body_extractions(ctx, url, resp.text or "")
            f = finding_from_hit(
                module=self.name,
                ftype="git_exposure",
                severity="critical" if conf >= 0.9 else "high",
                target=target,
                url=resp.url or url,
                title=title,
                evidence=(resp.text or "")[:300],
                confidence=conf,
                extracted=extracted,
                raw_ref=raw_ref,
                tags=["git"],
                validated=conf >= 0.9,
            )
            findings.append(f)
            ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
            if log:
                log.hit(resp.url or url, conf)

        # deeper follow-ups if HEAD valid
        if head_hit and not ctx.stop_event.is_set():
            for extra in ("/config", "/logs/HEAD", "/COMMIT_EDITMSG", "/description"):
                url = join_url(target.url, "/.git" + extra)
                resp = http.get(url)
                if resp.status_code == 200 and resp.text and not resp.soft404:
                    extracted = body_extractions(ctx, url, resp.text)
                    raw_ref = save_evidence(ctx, f"git_deep{extra}", resp.text)
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="git_exposure",
                            severity="critical",
                            target=target,
                            url=resp.url or url,
                            title=f"Git deep file {extra}",
                            evidence=resp.text[:300],
                            confidence=0.93,
                            extracted=extracted,
                            raw_ref=raw_ref,
                            tags=["git", "deep"],
                            validated=True,
                        )
                    )
                    ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
        return findings