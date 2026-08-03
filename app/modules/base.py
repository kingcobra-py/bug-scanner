"""Shared module helpers and ScanModule protocol."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Protocol, runtime_checkable

from app.extractors import extract_all
from app.extractors.cms_extractions import cms_body_extractions
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import safe_filename


@runtime_checkable
class ScanModule(Protocol):
    name: str

    def match(self, target: TargetContext) -> bool: ...

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]: ...


def save_evidence(ctx: ScanContext, name: str, content: str | bytes, ext: str = "txt") -> str:
    evid_dir = Path(ctx.output_dir) / "evidence"
    evid_dir.mkdir(parents=True, exist_ok=True)
    fname = safe_filename(name) + f".{ext}"
    path = evid_dir / fname
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content, encoding="utf-8", errors="ignore")
    # also append JSONL pointer
    jsonl = Path(ctx.output_dir) / "evidence.jsonl"
    with jsonl.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"file": str(path), "name": name}) + "\n")
    return str(path)


def body_extractions(ctx: ScanContext, url: str, body: str) -> dict:
    return extract_all(body, source_url=url, redact_values=ctx.config.redact_secrets)


def merge_extractions(*parts: dict) -> dict:
    merged: dict = {"secrets": [], "apis": [], "smtp": [], "endpoints": []}
    seen: set[str] = set()

    def ingest(items: list, bucket: str) -> None:
        for item in items or []:
            if not isinstance(item, dict):
                continue
            key = item.get("value_hash") or item.get("value")
            dedupe_key = f"{bucket}:{key}"
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            merged[bucket].append(item)

    for part in parts:
        ingest(part.get("secrets"), "secrets")
        ingest(part.get("apis"), "apis")
        ingest(part.get("smtp"), "smtp")
        for endpoint in part.get("endpoints") or []:
            if endpoint and endpoint not in merged["endpoints"]:
                merged["endpoints"].append(endpoint)
    return merged


def joomla_body_extractions(ctx: ScanContext, url: str, body: str) -> dict:
    return cms_body_extractions(ctx, url, body, joomla=True)


def emit_credential_findings(
    *,
    findings: list[Finding],
    target: TargetContext,
    ctx: ScanContext,
    module: str,
    url: str,
    path: str,
    body: str,
    extracted: dict,
    source_label: str,
    include_apis: bool = True,
) -> None:
    secrets = extracted.get("secrets") or []
    smtp = extracted.get("smtp") or []
    apis = extracted.get("apis") or [] if include_apis else []
    if not (secrets or smtp or apis):
        return

    slug = path.strip("/").replace("/", "_") or "home"
    raw_ref = save_evidence(ctx, f"{module}_extract_{slug}", body)

    if smtp:
        hosts = sorted(
            {
                str(item.get("value", {}).get("host", ""))
                for item in smtp
                if isinstance(item.get("value"), dict) and item.get("value", {}).get("host")
            }
        )
        findings.append(
            finding_from_hit(
                module=module,
                ftype="smtp",
                severity="critical",
                target=target,
                url=url,
                title=f"SMTP credentials extracted from {source_label}",
                evidence=", ".join(hosts) or f"{len(smtp)} SMTP record(s)",
                confidence=0.93,
                extracted={"smtp": smtp, "secrets": secrets},
                raw_ref=raw_ref,
                tags=[module, "smtp", "extract"],
                validated=True,
            )
        )
        ctx.progress.add_hit(secrets=len(smtp), module=module)

    if apis and include_apis:
        api_values = [str(item.get("value", "")) for item in apis[:8]]
        findings.append(
            finding_from_hit(
                module=module,
                ftype="api_key",
                severity="high",
                target=target,
                url=url,
                title=f"API endpoints/keys extracted from {source_label}",
                evidence=" | ".join(api_values)[:300],
                confidence=0.88,
                extracted={"apis": apis, "secrets": secrets, "smtp": smtp},
                raw_ref=raw_ref,
                tags=[module, "api", "extract"],
                validated=True,
            )
        )
        ctx.progress.add_hit(module=module)

    if secrets:
        kinds = sorted({str(s.get("kind", "")) for s in secrets if s.get("kind")})
        findings.append(
            finding_from_hit(
                module=module,
                ftype="js_secret",
                severity="critical",
                target=target,
                url=url,
                title=f"Secrets extracted from {source_label}",
                evidence=", ".join(kinds),
                confidence=0.9,
                extracted={"secrets": secrets, "smtp": smtp},
                raw_ref=raw_ref,
                tags=[module, "secrets", "extract"],
                validated=True,
            )
        )
        ctx.progress.add_hit(secrets=len(secrets), module=module)


def finding_from_hit(
    *,
    module: str,
    ftype: str,
    severity: str,
    target: TargetContext,
    url: str,
    title: str,
    evidence: str,
    confidence: float,
    extracted: dict | None = None,
    raw_ref: str = "",
    tags: list[str] | None = None,
    validated: bool = False,
) -> Finding:
    return Finding(
        type=ftype,
        severity=severity,
        target=target.url,
        url=url,
        title=title,
        evidence=evidence[:500],
        raw_ref=raw_ref,
        extracted=extracted or {},
        confidence=confidence,
        module=module,
        validated=validated,
        tags=tags or [],
    )