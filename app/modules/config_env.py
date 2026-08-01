"""Config / .env exposure module."""

from __future__ import annotations

from app.core.wordlists import load_wordlist, WORDLIST_DIR
from app.modules.base import body_extractions, finding_from_hit, save_http_response
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url


ENV_MARKERS = ("API_KEY", "SECRET", "PASSWORD", "DATABASE_URL", "AWS_", "MAIL_", "SMTP_", "TOKEN", "PRIVATE")


class ConfigEnvModule:
    name = "config"

    def __init__(self, extra_paths: list[str] | None = None) -> None:
        self.paths = load_wordlist(WORDLIST_DIR / "config_env.txt")
        if extra_paths:
            self.paths = list(dict.fromkeys([*self.paths, *extra_paths]))

    def match(self, target: TargetContext) -> bool:
        return bool(target.live)

    def _looks_like_env(self, text: str) -> bool:
        if not text:
            return False
        lines = [ln for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        if not lines:
            return False
        kv = sum(1 for ln in lines[:50] if "=" in ln)
        return kv >= 2 or any(m in text for m in ENV_MARKERS)

    def _looks_like_config(self, path: str, text: str, content_type: str) -> bool:
        low = (text or "")[:500].lower()
        ct = (content_type or "").lower()
        if path.endswith((".json",)) or "application/json" in ct:
            return text.strip().startswith("{") or text.strip().startswith("[")
        if path.endswith((".yml", ".yaml")):
            return ":" in text[:200]
        if path.endswith(".php") and ("<?php" in low or "define(" in low):
            return True
        if "appsettings" in path.lower():
            return "{" in text
        if "web.config" in path.lower():
            return "<configuration" in low
        if path.endswith(".env") or "/.env" in path or path.endswith("env"):
            return self._looks_like_env(text)
        return self._looks_like_env(text) or ("api" in low and "key" in low)

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        http = ctx.http
        log = ctx.logger
        ctx.progress.module_set_total(self.name, len(self.paths))

        for path in self.paths:
            if ctx.stop_event.is_set():
                break
            url = path if path.startswith("http") else join_url(target.url, path)
            resp = http.get(url)
            timed_out = bool(resp.error and "timeout" in resp.error)
            ctx.progress.tick(success=not bool(resp.error), timeout=timed_out, module=self.name)
            if resp.error or resp.soft404:
                continue
            if resp.status_code == 403 and resp.forbidden_but_exists:
                raw_ref = save_http_response(ctx, f"config_{path}", resp)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="env",
                        severity="medium",
                        target=target,
                        url=resp.url or url,
                        title=f"Config path forbidden-but-exists {path}",
                        evidence="HTTP 403 with body",
                        confidence=0.55,
                        raw_ref=raw_ref,
                        tags=["config", "forbidden"],
                    )
                )
                ctx.progress.add_hit(module=self.name)
                continue
            if resp.status_code != 200 or not resp.text:
                continue
            if not self._looks_like_config(path, resp.text, resp.headers.get("content-type", "")):
                continue

            extracted = body_extractions(ctx, resp.url or url, resp.text)
            raw_ref = save_http_response(ctx, f"config_{path}", resp)
            sev = "critical" if extracted.get("secrets") or extracted.get("smtp") else "high"
            f = finding_from_hit(
                module=self.name,
                ftype="env" if ".env" in path or self._looks_like_env(resp.text) else "path",
                severity=sev,
                target=target,
                url=resp.url or url,
                title=f"Exposed config/env {path}",
                evidence=resp.text[:300],
                confidence=0.9 if extracted.get("secrets") else 0.75,
                extracted=extracted,
                raw_ref=raw_ref,
                tags=["config", "env"],
                validated=bool(extracted.get("secrets") or extracted.get("smtp")),
            )
            findings.append(f)
            ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
            if log:
                log.hit(resp.url or url, f.confidence)
            ctx.bodies.append((resp.url or url, resp.text))
        return findings