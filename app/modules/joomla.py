"""
Joomla detection module with optional JCE RCE exploitation.
"""

from __future__ import annotations

from app.exploits.joomla_rce.detector import JoomlaJceDetector
from app.exploits.joomla_rce.exploit import JoomlaJceExploit
from app.modules.base import emit_credential_findings, finding_from_hit, joomla_body_extractions, save_http_response
from app.modules.vulnerability_intel import executable_upload_paths, jce_exposure, xml_version
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url

JOOMLA_PATHS = [
    "/",
    "/administrator/",
    "/administrator/index.php",
    "/configuration.php",
    "/configuration.php.bak",
    "/configuration.php.old",
    "/configuration.php~",
    "/README.txt",
    "/administrator/manifests/files/joomla.xml",
    "/language/en-GB/en-GB.xml",
    "/plugins/editors/jce/jce.xml",
    "/plugins/system/jcemediabox/js/jcemediabox.js",
    "/plugins/system/jce/css/content.css",
    "/administrator/components/com_jce/jce.xml",
    "/index.php?option=com_jce&task=cpanel.feed",
    "/images/",
    "/api/index.php/v1",
    "/api/index.php/v1/content/articles",
    "/api/index.php/v1/users",
]

EXTRACT_PATHS = {
    "/",
    "/administrator/",
    "/configuration.php",
    "/configuration.php.bak",
    "/configuration.php.old",
    "/configuration.php~",
    "/api/index.php/v1",
    "/api/index.php/v1/content/articles",
    "/api/index.php/v1/users",
    "/index.php?option=com_jce&task=cpanel.feed",
}


class JoomlaModule:
    name = "joomla"

    def match(self, target: TargetContext) -> bool:
        return bool(target.live)

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        http = ctx.http
        is_joomla = "joomla" in (target.tech or [])

        ctx.progress.module_set_total(self.name, len(JOOMLA_PATHS))

        for path in JOOMLA_PATHS:
            if ctx.stop_event.is_set():
                break
            url = join_url(target.url, path)
            resp = http.get(url)
            timed_out = bool(resp.error and "timeout" in resp.error)
            ctx.progress.tick(success=not bool(resp.error), timeout=timed_out, module=self.name)
            if resp.error or resp.soft404:
                continue
            body = resp.text or ""
            extracted = (
                joomla_body_extractions(ctx, resp.url or url, body)
                if resp.status_code == 200 and body and path in EXTRACT_PATHS
                else {"secrets": [], "apis": [], "smtp": [], "endpoints": []}
            )

            if path in {"/", "/administrator/", "/administrator/index.php"} and resp.status_code in (200, 401, 403):
                if "joomla" in body.lower() or is_joomla or "com_login" in body.lower() or path == "/":
                    if "joomla" in body.lower() or "com_login" in body.lower() or "generator" in body.lower():
                        is_joomla = True
                    if "administrator" in path and (
                        "joomla" in body.lower() or is_joomla or "com_login" in body.lower()
                    ):
                        findings.append(
                            finding_from_hit(
                                module=self.name,
                                ftype="other",
                                severity="info",
                                target=target,
                                url=resp.url or url,
                                title="Joomla administrator panel detected",
                                evidence=body[:200],
                                confidence=0.85,
                                tags=["joomla", "fingerprint"],
                            )
                        )
                        ctx.progress.add_hit(module=self.name)

            if path.startswith("/configuration.php") and resp.status_code == 200 and (
                "public $" in body or "JConfig" in body or "dbpassword" in body.lower() or "$password" in body
            ):
                raw_ref = save_http_response(ctx, f"joomla_config_{path}", resp)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="env",
                        severity="critical",
                        target=target,
                        url=resp.url or url,
                        title="Exposed Joomla configuration.php",
                        evidence=body[:300],
                        confidence=0.95,
                        extracted=extracted,
                        raw_ref=raw_ref,
                        tags=["joomla", "config", "extract"],
                        validated=True,
                    )
                )
                ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
                emit_credential_findings(
                    findings=findings,
                    target=target,
                    ctx=ctx,
                    module=self.name,
                    url=resp.url or url,
                    path=path,
                    body=body,
                    extracted=extracted,
                    source_label=f"configuration.php ({path})",
                    include_apis=False,
                )

            if path.endswith("jce.xml") and resp.status_code == 200 and len(body) > 20:
                is_joomla = True
                version = xml_version(body)
                raw_ref = save_http_response(ctx, f"jce_xml_{path}", resp)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="low",
                        target=target,
                        url=resp.url or url,
                        title="JCE editor component path exposed",
                        evidence=body[:200] if not version else f"JCE version {version}",
                        confidence=0.8 if version else 0.65,
                        extracted={"jce_version": version} if version else {},
                        raw_ref=raw_ref,
                        tags=["joomla", "jce", "detection-only"],
                    )
                )
                ctx.progress.add_hit(module=self.name)
                exposure = jce_exposure(version)
                if exposure:
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="vuln",
                            severity=exposure["severity"],
                            target=target,
                            url=resp.url or url,
                            title=f"JCE {version} matches CVE-2026-48907 exposure range",
                            evidence=(
                                f"JCE {version}; exposure: {exposure['exposure']}; "
                                f"remediation: {exposure['fixed']}"
                            ),
                            confidence=0.93,
                            extracted=exposure,
                            raw_ref=raw_ref,
                            tags=["joomla", "jce", "cve-2026-48907", "detection-only"],
                            validated=True,
                        )
                    )
                    ctx.progress.add_hit(module=self.name)
                continue

            if "jce" in path and resp.status_code == 200 and not resp.soft404 and len(body) > 20:
                is_joomla = True
                title = "JCE editor component path exposed"
                severity = "low"
                tags = ["joomla", "jce", "detection-only"]
                if "cpanel.feed" in path and '"feeds"' in body:
                    title = "JCE cpanel.feed proxy endpoint reachable"
                    severity = "medium"
                    tags = ["joomla", "jce", "cve-2026-48907", "detection-only"]
                raw_ref = save_http_response(ctx, f"joomla_jce_{path}", resp)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity=severity,
                        target=target,
                        url=resp.url or url,
                        title=title,
                        evidence=body[:200],
                        confidence=0.7 if "feeds" in body else 0.65,
                        raw_ref=raw_ref,
                        tags=tags,
                    )
                )
                ctx.progress.add_hit(module=self.name)

            if path in {"/administrator/manifests/files/joomla.xml", "/language/en-GB/en-GB.xml", "/README.txt"}:
                version = xml_version(body) if path.endswith(".xml") else None
                if version or ("joomla" in body.lower() and resp.status_code == 200):
                    is_joomla = True
                    raw_ref = save_http_response(ctx, f"joomla_version_{path}", resp)
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="other",
                            severity="info",
                            target=target,
                            url=resp.url or url,
                            title="Joomla version artifact exposed" if version else "Joomla documentation artifact exposed",
                            evidence=version or body[:200],
                            confidence=0.85 if version else 0.6,
                            extracted={"joomla_version": version} if version else {},
                            raw_ref=raw_ref,
                            tags=["joomla", "version-check", "detection-only"],
                        )
                    )
                    ctx.progress.add_hit(module=self.name)

            if path == "/images/" and resp.status_code == 200:
                for shell_path in executable_upload_paths(body):
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="path",
                            severity="high",
                            target=target,
                            url=join_url(target.url, shell_path),
                            title="Executable file listed under /images",
                            evidence=shell_path,
                            confidence=0.8,
                            tags=["joomla", "webshell-indicator", "detection-only"],
                        )
                    )
                    ctx.progress.add_hit(module=self.name)

            if path.startswith("/api/index.php") and resp.status_code in (200, 401, 403) and body:
                is_joomla = True
                raw_ref = save_http_response(ctx, f"joomla_api_{path}", resp)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="medium",
                        target=target,
                        url=resp.url or url,
                        title="Joomla Web Services API endpoint reachable",
                        evidence=body[:200],
                        confidence=0.85,
                        raw_ref=raw_ref,
                        tags=["joomla", "api", "webservices", "detection-only"],
                    )
                )
                ctx.progress.add_hit(module=self.name)

            if resp.status_code == 200 and path in EXTRACT_PATHS and not path.startswith("/configuration.php"):
                label = "Joomla response" if path == "/" else path
                emit_credential_findings(
                    findings=findings,
                    target=target,
                    ctx=ctx,
                    module=self.name,
                    url=resp.url or url,
                    path=path,
                    body=body,
                    extracted=extracted,
                    source_label=label,
                    include_apis=False,
                )

        if is_joomla and not any("Joomla" in f.title for f in findings):
            findings.append(
                finding_from_hit(
                    module=self.name,
                    ftype="other",
                    severity="info",
                    target=target,
                    url=target.url,
                    title="Joomla fingerprint",
                    evidence=",".join(target.tech),
                    confidence=0.7,
                    tags=["joomla", "fingerprint"],
                )
            )

        home = http.get(target.url)
        detector = JoomlaJceDetector(http, target.url)
        scan = detector.scan(home if home.status_code == 200 else None)
        pre_met = int(scan.get("preconditions_met") or 0)
        pre_total = int(scan.get("preconditions_total") or 3)
        if pre_met >= 2:
            severity = "critical" if scan.get("chain_ready") else "high"
            findings.append(
                finding_from_hit(
                    module=self.name,
                    ftype="vuln" if scan.get("chain_ready") else "other",
                    severity=severity,
                    target=target,
                    url=target.url,
                    title=(
                        "JCE CVE-2026-48907 chain preconditions satisfied (joomla PoC surface)"
                        if scan.get("chain_ready")
                        else f"JCE exploit preconditions {pre_met}/{pre_total} (joomla PoC surface)"
                    ),
                    evidence=(
                        f"jce={scan.get('jce_present')}; proxy={scan.get('proxy_reachable')}; "
                        f"csrf={scan.get('csrf_token_present')}; version={scan.get('jce_version')}; "
                        f"poc={scan.get('poc_source')}"
                    ),
                    confidence=0.94 if scan.get("chain_ready") else 0.78,
                    extracted=scan,
                    tags=["joomla", "jce", "cve-2026-48907", "detection-only"],
                    validated=bool(scan.get("chain_ready")),
                )
            )
            ctx.progress.add_hit(module=self.name)

        # ===== ACTIVE EXPLOITATION =====
        if ctx.exploit_enabled and is_joomla:
            exploit = JoomlaJceExploit(http, target.url)
            success, shell_url = exploit.run()
            if success:
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="vuln",
                        severity="critical",
                        target=target,
                        url=target.url,
                        title="Joomla JCE RCE (CVE-2026-48907) active",
                        evidence=f"Shell at: {shell_url}",
                        confidence=1.0,
                        tags=["joomla", "rce", "jce", "cve-2026-48907", "active-exploit"],
                        validated=True,
                    )
                )
                ctx.progress.add_hit(module=self.name)
                secrets = exploit.extract_secrets(ctx)
                for category, lines in secrets.items():
                    if lines:
                        findings.append(
                            finding_from_hit(
                                module=self.name,
                                ftype="secrets",
                                severity="high",
                                target=target,
                                url=target.url,
                                title=f"Secret extraction: {category} (Joomla RCE)",
                                evidence="\n".join(lines[:20]),
                                confidence=0.95,
                                tags=["joomla", "secrets", category, "active-exploit"],
                                validated=True,
                            )
                        )
                        ctx.progress.add_hit(secrets=len(lines), module=self.name)

        return findings
