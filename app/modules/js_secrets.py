"""JS path discovery + secret/API extraction from bundles and source maps."""

from __future__ import annotations

from app.core.crawler import crawl_target
from app.core.wordlists import load_wordlist, WORDLIST_DIR
from app.modules.base import body_extractions, finding_from_hit, save_http_response
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import join_url


class JsSecretsModule:
    name = "js"

    def __init__(self, extra_paths: list[str] | None = None) -> None:
        self.paths = load_wordlist(WORDLIST_DIR / "js_paths.txt")
        if extra_paths:
            self.paths = list(dict.fromkeys([*self.paths, *extra_paths]))

    def match(self, target: TargetContext) -> bool:
        return bool(target.live)

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        http = ctx.http
        log = ctx.logger

        crawl = crawl_target(http, target.url)
        script_urls = list(dict.fromkeys([
            *(join_url(target.url, p) if not p.startswith("http") else p for p in self.paths),
            *crawl.get("scripts", []),
        ]))
        # drop glob-like placeholders
        script_urls = [u for u in script_urls if "*" not in u]

        ctx.progress.module_set_total(self.name, len(script_urls))
        for url in script_urls:
            if ctx.stop_event.is_set():
                break
            resp = http.get(url)
            timed_out = bool(resp.error and "timeout" in resp.error)
            ctx.progress.tick(success=not bool(resp.error), timeout=timed_out, module=self.name)
            if resp.error or resp.status_code != 200 or resp.soft404:
                continue
            body = resp.text or ""
            if len(body) < 20:
                continue
            # skip obvious HTML soft pages
            if "<html" in body[:200].lower() and ".js" in url and "sourceMappingURL" not in body:
                # might still be a JS file with HTML error — ignore if looks like HTML doc
                if "</html>" in body.lower() and "function" not in body[:500]:
                    continue

            extracted = body_extractions(ctx, resp.url or url, body)
            secrets = extracted.get("secrets", [])
            apis = extracted.get("apis", [])
            smtp = extracted.get("smtp", [])
            if not (secrets or apis or smtp):
                # still record interesting source maps / large configs lightly as info if map
                if url.endswith(".map") and ("sourcesContent" in body or "mappings" in body):
                    raw_ref = save_http_response(ctx, f"jsmap_{url}", resp)
                    findings.append(
                        finding_from_hit(
                            module=self.name,
                            ftype="path",
                            severity="info",
                            target=target,
                            url=resp.url or url,
                            title="JavaScript source map exposed",
                            evidence=body[:200],
                            confidence=0.7,
                            extracted=extracted,
                            raw_ref=raw_ref,
                            tags=["js", "sourcemap"],
                        )
                    )
                    ctx.progress.add_hit(module=self.name)
                continue

            raw_ref = save_http_response(ctx, f"js_{url}", resp)
            severity = "critical" if secrets or smtp else "medium"
            f = finding_from_hit(
                module=self.name,
                ftype="js_secret" if secrets else "api_key",
                severity=severity,
                target=target,
                url=resp.url or url,
                title=f"Secrets/APIs in JS ({len(secrets)} secrets, {len(apis)} apis, {len(smtp)} smtp)",
                evidence=body[:200],
                confidence=0.85 if secrets else 0.7,
                extracted=extracted,
                raw_ref=raw_ref,
                tags=["js"],
                validated=bool(secrets),
            )
            findings.append(f)
            ctx.progress.add_hit(
                secrets=len(secrets) + len(smtp),
                module=self.name,
            )
            if log:
                log.hit(resp.url or url, f.confidence)
                log.info(
                    "extraction summary secrets=%d apis=%d smtp=%d",
                    len(secrets),
                    len(apis),
                    len(smtp),
                )
            ctx.bodies.append((resp.url or url, body))
        return findings