"""HTTP method probing on prioritized endpoints."""

from __future__ import annotations

from urllib.parse import urlparse

from app.modules.base import finding_from_hit, save_method_responses
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url


PRIORITY_PATHS = [
    "/",
    "/login",
    "/admin",
    "/administrator",
    "/wp-login.php",
    "/wp-admin",
    "/api",
    "/api/v1",
    "/graphql",
    "/upload",
    "/uploads",
]


class MethodTesterModule:
    name = "methods"

    def match(self, target: TargetContext) -> bool:
        return bool(target.live)

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        http = ctx.http
        methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        if ctx.config.method_test_trace:
            methods.append("TRACE")

        endpoints = [join_url(target.url, p) for p in PRIORITY_PATHS]
        # include discovered API endpoints from prior findings/bodies
        for f in list(ctx.findings):
            for ep in (f.extracted or {}).get("endpoints", [])[:20]:
                if isinstance(ep, str) and ep.startswith("http"):
                    endpoints.append(ep)
        # unique preserve
        seen = set()
        endpoints = [e for e in endpoints if not (e in seen or seen.add(e))]

        ctx.progress.module_set_total(self.name, len(endpoints))
        for url in endpoints:
            if ctx.stop_event.is_set():
                break
            results = http.test_methods(url, methods, include_override=True)
            ctx.progress.tick(success=True, module=self.name)
            allowed = []
            interesting = []
            allow_header = ""
            for r in results:
                if r.error:
                    continue
                if r.status_code and r.status_code < 500:
                    # treat 405 as not allowed
                    if r.status_code != 405:
                        allowed.append(f"{r.method}:{r.status_code}")
                    if r.method in ("PUT", "DELETE", "PATCH", "TRACE") and r.status_code not in (401, 403, 404, 405, 501):
                        interesting.append(f"{r.method}:{r.status_code}")
                    allow_header = allow_header or r.headers.get("allow", "")
            # detect override success: POST with override header returned non-405 while POST itself may differ
            override_hits = [
                r for r in results
                if r.method == "POST" and r.status_code not in (0, 404, 405, 501) and not r.error
            ]
            parsed = urlparse(url)
            host = parsed.netloc or "host"
            path = parsed.path or "/"
            bundle_name = f"methods_{host}_{path}"

            # Flag only if dangerous methods appear accepted
            if interesting:
                raw_ref = save_method_responses(ctx, bundle_name, url, results)
                evidence = f"allowed={allowed}; allow_header={allow_header}; interesting={interesting}"
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="medium",
                        target=target,
                        url=url,
                        title="Unexpected HTTP methods accepted",
                        evidence=evidence[:500],
                        confidence=0.7,
                        extracted={"endpoints": [url], "methods": allowed},
                        raw_ref=raw_ref,
                        tags=["methods"],
                    )
                )
                ctx.progress.add_hit(module=self.name)
            elif allow_header and any(m in allow_header.upper() for m in ("PUT", "DELETE", "TRACE")):
                raw_ref = save_method_responses(ctx, bundle_name, url, results)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="other",
                        severity="low",
                        target=target,
                        url=url,
                        title="Allow header advertises risky methods",
                        evidence=f"Allow: {allow_header}",
                        confidence=0.6,
                        extracted={"endpoints": [url], "methods": [allow_header]},
                        raw_ref=raw_ref,
                        tags=["methods"],
                    )
                )
                ctx.progress.add_hit(module=self.name)
            # OPTIONS body often lists methods — already covered via allow header
            _ = override_hits
        return findings
