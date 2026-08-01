"""
WordPress detection module (SAFE).

Does NOT integrate or execute wp2shell / RCE exploit payloads.
Performs fingerprinting, version exposure scoring, sensitive path checks, and extraction only.
"""

from __future__ import annotations

from app.modules.base import body_extractions, finding_from_hit, save_evidence
from app.modules.vulnerability_intel import executable_upload_paths, wordpress_exposure, wordpress_version
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url

WP_PATHS = [
    "/wp-login.php",
    "/wp-admin/",
    "/xmlrpc.php",
    "/wp-json/",
    "/wp-json/batch/v1",
    "/?rest_route=/batch/v1",
    "/wp-json/wp/v2/users",
    "/wp-config.php",
    "/wp-config.php.bak",
    "/wp-config.php.old",
    "/wp-config.php.save",
    "/wp-config.php~",
    "/wp-config.bak",
    "/wp-config.txt",
    "/wp-content/debug.log",
    "/wp-content/uploads/",
    "/readme.html",
]

BATCH_MARKERS = (
    "rest_route",
    "batch",
    "namespace",
    "routes",
    "validation_error",
    "rest_no_route",
    "rest_forbidden",
    "rest_cookie_invalid_nonce",
)


class WordPressModule:
    name = "wordpress"

    def match(self, target: TargetContext) -> bool:
        return bool(target.live)

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        http = ctx.http
        is_wp = "wordpress" in (target.tech or [])
        version = str((target.meta or {}).get("wordpress_version") or "") or None
        ctx.progress.module_set_total(self.name, len(WP_PATHS) + 1)

        home = http.get(target.url)
        ctx.progress.tick(
            success=not bool(home.error),
            timeout=bool(home.error and "timeout" in home.error),
            module=self.name,
        )
        if home.status_code == 200 and home.text:
            detected = wordpress_version(home.text)
            if detected:
                is_wp = True
                version = detected
            shell_paths = executable_upload_paths(home.text)
            for shell_path in shell_paths:
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="path",
                        severity="high",
                        target=target,
                        url=join_url(target.url, shell_path),
                        title="Executable upload path referenced in WordPress response",
                        evidence=shell_path,
                        confidence=0.7,
                        tags=["wordpress", "webshell-indicator", "detection-only"],
                    )
                )
                ctx.progress.add_hit(module=self.name)

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
                detected = wordpress_version(body)
                if detected:
                    version = detected
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
            if path.startswith("/wp-config") and resp.status_code == 200 and (
                "DB_NAME" in body or "DB_PASSWORD" in body or "<?php" in body
            ):
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
            if path == "/xmlrpc.php" and resp.status_code == 200 and (
                "XML-RPC" in body
                or "methodResponse" in body
                or resp.headers.get("content-type", "").startswith("text/xml")
            ):
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
                is_wp = True
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
            if path in {"/wp-json/batch/v1", "/?rest_route=/batch/v1"} and resp.status_code in (
                200,
                400,
                401,
                403,
                405,
            ):
                body_l = body.lower()
                if any(marker in body_l for marker in BATCH_MARKERS) or "batch" in (resp.url or url).lower():
                    is_wp = True
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="other",
                            severity="medium",
                            target=target,
                            url=resp.url or url,
                            title="WordPress REST batch endpoint reachable",
                            evidence=f"status={resp.status_code}; {body[:180]}",
                            confidence=0.82,
                            tags=["wordpress", "wp2shell", "batch-endpoint", "detection-only"],
                        )
                    )
                    ctx.progress.add_hit(module=self.name)
            if path == "/wp-json/wp/v2/users" and resp.status_code == 200 and ("slug" in body or "name" in body):
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="medium",
                        target=target,
                        url=resp.url or url,
                        title="WordPress user enumeration via REST API",
                        evidence=body[:200],
                        confidence=0.8,
                        tags=["wordpress", "users", "detection-only"],
                    )
                )
                ctx.progress.add_hit(module=self.name)
            if path == "/wp-content/uploads/" and resp.status_code == 200:
                for shell_path in executable_upload_paths(body):
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="path",
                            severity="high",
                            target=target,
                            url=join_url(target.url, shell_path),
                            title="Executable file listed under wp-content/uploads",
                            evidence=shell_path,
                            confidence=0.78,
                            tags=["wordpress", "webshell-indicator", "detection-only"],
                        )
                    )
                    ctx.progress.add_hit(module=self.name)
            if path == "/readme.html" and resp.status_code == 200:
                detected = wordpress_version(body)
                if detected:
                    is_wp = True
                    version = detected

        if version:
            exposure = wordpress_exposure(version)
            if exposure:
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="vuln",
                        severity=exposure["severity"],
                        target=target,
                        url=target.url,
                        title=f"WordPress {version} matches {exposure['exposure']}",
                        evidence=(
                            f"WordPress {version}; CVEs: {', '.join(exposure['cves'])}; "
                            f"remediation: {exposure['fixed']}"
                        ),
                        confidence=0.9,
                        extracted=exposure,
                        tags=["wordpress", "wp2shell", "version-check", "detection-only"],
                        validated=True,
                    )
                )
                ctx.progress.add_hit(module=self.name)
            else:
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="info",
                        target=target,
                        url=target.url,
                        title=f"WordPress version detected: {version}",
                        evidence=version,
                        confidence=0.8,
                        tags=["wordpress", "version-check"],
                    )
                )

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
        return findings
