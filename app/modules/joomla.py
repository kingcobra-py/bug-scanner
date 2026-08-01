"""
Joomla detection module (SAFE).

Does NOT integrate Joomla RCE / webshell upload PoCs.
Checks for Joomla presence, admin panel, and sensitive component paths only.
"""

from __future__ import annotations

from app.modules.base import body_extractions, finding_from_hit, save_evidence
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url

JOOMLA_PATHS = [
    "/administrator/",
    "/administrator/index.php",
    "/configuration.php",
    "/configuration.php.bak",
    "/configuration.php.old",
    "/configuration.php~",
    "/README.txt",
    "/plugins/editors/jce/jce.xml",
    "/plugins/system/jcemediabox/js/jcemediabox.js",
    "/administrator/components/com_jce/jce.xml",
    "/api/index.php/v1",
]


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
            if "administrator" in path and resp.status_code in (200, 401, 403) and (
                "joomla" in body.lower() or "administrator" in (resp.url or "").lower() or resp.status_code in (200, 403)
            ):
                # tighten: need joomla signal unless tech already known
                if "joomla" in body.lower() or is_joomla or "com_login" in body.lower():
                    is_joomla = True
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
                "public $" in body or "JConfig" in body or "dbpassword" in body.lower()
            ):
                extracted = body_extractions(ctx, url, body)
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
                        tags=["joomla", "config"],
                        validated=True,
                    )
                )
                ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
            if "jce" in path and resp.status_code == 200 and not resp.soft404 and len(body) > 20:
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="low",
                        target=target,
                        url=resp.url or url,
                        title="JCE editor component path exposed",
                        evidence=body[:200],
                        confidence=0.65,
                        tags=["joomla", "jce", "detection-only"],
                    )
                )
                ctx.progress.add_hit(module=self.name)
        return findings