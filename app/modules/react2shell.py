"""
React / Next.js detection module (SAFE).

Does NOT integrate React2Shell / RSC RCE exploit payloads (e.g. CVE-2025-55182 style PoCs).
Fingerprints Next/React and checks for exposed _next assets / env leaks only.
"""

from __future__ import annotations

from app.modules.base import body_extractions, finding_from_hit, save_evidence
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url

NEXT_PATHS = [
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/main-app.js",
    "/_next/static/chunks/framework.js",
    "/robots.txt",
]


class ReactModule:
    name = "react"

    def match(self, target: TargetContext) -> bool:
        return bool(target.live)

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        http = ctx.http
        tech = set(target.tech or [])
        ctx.progress.module_set_total(self.name, len(NEXT_PATHS) + 1)

        # homepage already fingerprinted; still check __NEXT_DATA__
        home = http.get(target.url)
        ctx.progress.tick(success=not bool(home.error), timeout=bool(home.error and "timeout" in home.error), module=self.name)
        if home.status_code == 200 and home.text:
            if "__NEXT_DATA__" in home.text or "/_next/static/" in home.text:
                tech.update({"nextjs", "react"})
                extracted = body_extractions(ctx, home.url or target.url, home.text)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="info",
                        target=target,
                        url=home.url or target.url,
                        title="Next.js application detected",
                        evidence="__NEXT_DATA__ or /_next/static present",
                        confidence=0.9,
                        extracted=extracted,
                        tags=["nextjs", "react", "fingerprint"],
                    )
                )
                ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
                # extract inline next data block for secrets
                if extracted.get("secrets") or extracted.get("apis"):
                    raw_ref = save_evidence(ctx, "next_home", home.text[: ctx.config.max_body_bytes])
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="js_secret",
                            severity="high",
                            target=target,
                            url=home.url or target.url,
                            title="Secrets/APIs in Next.js HTML bootstrap",
                            evidence=home.text[:200],
                            confidence=0.8,
                            extracted=extracted,
                            raw_ref=raw_ref,
                            tags=["nextjs", "extract"],
                        )
                    )

        for path in NEXT_PATHS:
            if ctx.stop_event.is_set():
                break
            url = join_url(target.url, path)
            resp = http.get(url)
            timed_out = bool(resp.error and "timeout" in resp.error)
            ctx.progress.tick(success=not bool(resp.error), timeout=timed_out, module=self.name)
            if resp.error or resp.soft404 or resp.status_code != 200:
                continue
            if "/_next/" in path:
                tech.update({"nextjs", "react"})
                extracted = body_extractions(ctx, resp.url or url, resp.text or "")
                if extracted.get("secrets") or extracted.get("apis") or extracted.get("smtp"):
                    raw_ref = save_evidence(ctx, f"next_{path}", resp.text or "")
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="js_secret",
                            severity="high",
                            target=target,
                            url=resp.url or url,
                            title=f"Secrets/APIs in Next asset {path}",
                            evidence=(resp.text or "")[:200],
                            confidence=0.85,
                            extracted=extracted,
                            raw_ref=raw_ref,
                            tags=["nextjs", "js"],
                        )
                    )
                    ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
        return findings