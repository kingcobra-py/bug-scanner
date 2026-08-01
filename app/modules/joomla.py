"""
Joomla detection module (SAFE).

Does NOT integrate Joomla RCE / webshell upload PoCs.
Checks for Joomla presence, admin panel, JCE versions, webshell indicators,
and extracts APIs/credentials with Joomla-specific patterns.
"""

from __future__ import annotations

from app.extractors.joomla_api_extractor import extract_joomla_apis
from app.modules.base import finding_from_hit, save_evidence
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


def _merge_joomla_extract(body: str, url: str, redact: bool) -> dict:
    extracted = extract_joomla_apis(body, source_url=url, redact_values=redact)
    return {
        "apis": extracted.get("apis", []),
        "secrets": extracted.get("secrets", []),
        "endpoints": extracted.get("endpoints", []),
        "smtp": [],
        "extractor": "joomla",
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
        redact = ctx.config.redact_secrets

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
            extracted = _merge_joomla_extract(body, resp.url or url, redact) if resp.status_code == 200 and body else {
                "apis": [],
                "secrets": [],
                "endpoints": [],
                "smtp": [],
                "extractor": "joomla",
            }

            if path in {"/", "/administrator/", "/administrator/index.php"} and resp.status_code in (200, 401, 403):
                if "joomla" in body.lower() or is_joomla or "com_login" in body.lower() or path == "/":
                    if "joomla" in body.lower() or "com_login" in body.lower() or "generator" in body.lower():
                        is_joomla = True
                    if path != "/" or is_joomla or "joomla" in body.lower():
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
                raw_ref = save_evidence(ctx, f"joomla_config_{path}", body)
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
                        tags=["joomla", "config", "joomla-api-extract"],
                        validated=True,
                    )
                )
                ctx.progress.add_hit(
                    secrets=len(extracted.get("secrets", [])),
                    module=self.name,
                )
                if extracted.get("apis"):
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="api_key",
                            severity="high",
                            target=target,
                            url=resp.url or url,
                            title="Joomla APIs/endpoints extracted from configuration.php",
                            evidence="; ".join(a.get("value", "") for a in extracted["apis"][:5]),
                            confidence=0.9,
                            extracted=extracted,
                            raw_ref=raw_ref,
                            tags=["joomla", "api", "joomla-api-extract"],
                        )
                    )
                    ctx.progress.add_hit(module=self.name)

            if path.endswith("jce.xml") and resp.status_code == 200 and len(body) > 20:
                is_joomla = True
                version = xml_version(body)
                raw_ref = save_evidence(ctx, f"jce_xml_{path}", body)
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
                        extracted=extracted if extracted.get("apis") else {},
                        tags=tags,
                    )
                )
                ctx.progress.add_hit(module=self.name)

            if path in {"/administrator/manifests/files/joomla.xml", "/language/en-GB/en-GB.xml", "/README.txt"}:
                version = xml_version(body) if path.endswith(".xml") else None
                if version or ("joomla" in body.lower() and resp.status_code == 200):
                    is_joomla = True
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
                        extracted=extracted,
                        tags=["joomla", "api", "webservices", "joomla-api-extract"],
                    )
                )
                ctx.progress.add_hit(module=self.name)
                if extracted.get("apis") or extracted.get("secrets"):
                    raw_ref = save_evidence(ctx, f"joomla_api_{path}", body)
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="api_key" if extracted.get("secrets") else "other",
                            severity="high" if extracted.get("secrets") else "medium",
                            target=target,
                            url=resp.url or url,
                            title="Joomla APIs extracted via Joomla pattern pack",
                            evidence="; ".join(
                                [a.get("value", "") for a in extracted.get("apis", [])[:5]]
                                + [s.get("kind", "") for s in extracted.get("secrets", [])[:3]]
                            ),
                            confidence=0.9,
                            extracted=extracted,
                            raw_ref=raw_ref,
                            tags=["joomla", "api", "joomla-api-extract"],
                        )
                    )
                    ctx.progress.add_hit(
                        secrets=len(extracted.get("secrets", [])),
                        module=self.name,
                    )

            # Generic Joomla-body API hits on homepage / admin HTML
            if path in {"/", "/administrator/"} and resp.status_code == 200 and extracted.get("apis"):
                raw_ref = save_evidence(ctx, f"joomla_html_apis_{path.strip('/') or 'home'}", body)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="medium",
                        target=target,
                        url=resp.url or url,
                        title="Joomla APIs extracted from HTML via Joomla pattern pack",
                        evidence="; ".join(a.get("value", "") for a in extracted["apis"][:5]),
                        confidence=0.82,
                        extracted=extracted,
                        raw_ref=raw_ref,
                        tags=["joomla", "api", "joomla-api-extract"],
                    )
                )
                ctx.progress.add_hit(module=self.name)

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
        return findings
