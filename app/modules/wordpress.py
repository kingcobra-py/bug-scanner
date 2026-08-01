"""
WordPress detection module (SAFE).

Does NOT integrate or execute wp2shell / RCE exploit payloads.
Performs fingerprinting, exposed sensitive WP path checks, and extraction only.
"""

from __future__ import annotations

from app.modules.base import body_extractions, finding_from_hit, save_evidence
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url

WP_PATHS = [
    "/wp-login.php",
    "/wp-admin/",
    "/xmlrpc.php",
    "/wp-json/",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php.save",
    "/wp-config.php~",
    "/wp-content/debug.log",
    "/readme.html",
]


class WordPressModule:
    name = "wordpress"

    def match(self, target: TargetContext) -> bool:
        return target.live and ("wordpress" in (target.tech or []) or True)

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        http = ctx.http
        # quick confirm
        is_wp = "wordpress" in (target.tech or [])
        ctx.progress.module_set_total(self.name, len(WP_PATHS))
        for path in WP_PATHS:
            if ctx.stop_event.is_set():
                break
            url = join_url(target.url, path)
            resp = http.get(url)
            timed_out = bool(resp.error and "timeout" in resp.error)
            ctx.progress.tick(success=not bool(resp.error), timeout=timed_out, module=self.name)
            if resp.error or resp.soft404:
                continue
            body = resp.text or ""
            if path == "/wp-login.php" and resp.status_code in (200, 401, 403):
                is_wp = True
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="info",
                        target=target,
                        url=resp.url or url,
                        title="WordPress login detected",
                        evidence=body[:200],
                        confidence=0.85,
                        tags=["wordpress", "fingerprint"],
                    )
                )
                ctx.progress.add_hit(module=self.name)
            if path.startswith("/wp-config.php") and resp.status_code == 200 and ("DB_NAME" in body or "DB_PASSWORD" in body or "<?php" in body):
                extracted = body_extractions(ctx, url, body)
                raw_ref = save_evidence(ctx, f"wp_config_{path}", body)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="env",
                        severity="critical",
                        target=target,
                        url=resp.url or url,
                        title="Exposed wp-config.php",
                        evidence=body[:300],
                        confidence=0.95,
                        extracted=extracted,
                        raw_ref=raw_ref,
                        tags=["wordpress", "config"],
                        validated=True,
                    )
                )
                ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
            if path == "/wp-content/debug.log" and resp.status_code == 200 and len(body) > 50:
                extracted = body_extractions(ctx, url, body)
                raw_ref = save_evidence(ctx, "wp_debug_log", body)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="path",
                        severity="high",
                        target=target,
                        url=resp.url or url,
                        title="WordPress debug.log exposed",
                        evidence=body[:300],
                        confidence=0.85,
                        extracted=extracted,
                        raw_ref=raw_ref,
                        tags=["wordpress", "log"],
                    )
                )
                ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
            if path == "/xmlrpc.php" and resp.status_code == 200 and ("XML-RPC" in body or "methodResponse" in body or resp.headers.get("content-type", "").startswith("text/xml")):
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="low",
                        target=target,
                        url=resp.url or url,
                        title="WordPress XML-RPC enabled",
                        evidence=body[:200],
                        confidence=0.75,
                        tags=["wordpress", "xmlrpc"],
                    )
                )
                ctx.progress.add_hit(module=self.name)
            if path == "/wp-json/" and resp.status_code == 200 and ("namespaces" in body or "name" in body):
                extracted = body_extractions(ctx, url, body)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="api_key" if extracted.get("apis") else "other",
                        severity="info",
                        target=target,
                        url=resp.url or url,
                        title="WordPress REST API exposed",
                        evidence=body[:200],
                        confidence=0.8,
                        extracted=extracted,
                        tags=["wordpress", "api"],
                    )
                )
                ctx.progress.add_hit(module=self.name)

        if is_wp and not any(f.title.startswith("WordPress") for f in findings):
            findings.append(
                finding_from_hit(
                    module=self.name,
                    ftype="other",
                    severity="info",
                    target=target,
                    url=target.url,
                    title="WordPress fingerprint",
                    evidence=",".join(target.tech),
                    confidence=0.7,
                    tags=["wordpress", "fingerprint"],
                )
            )
        # Explicit notice: RCE exploit integration intentionally omitted
        return findings