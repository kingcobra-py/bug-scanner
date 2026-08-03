"""Shared module helpers and ScanModule protocol."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Iterable, Iterator, Protocol, runtime_checkable

from app.extractors import extract_all
from app.extractors.cms_extractions import cms_body_extractions
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import host_key, safe_filename

if TYPE_CHECKING:
    from app.core.http_client import HttpResponse

_finding_stream = threading.local()


@runtime_checkable
class ScanModule(Protocol):
    name: str

    def match(self, target: TargetContext) -> bool: ...

    def run(self, target: TargetContext, ctx: ScanContext) -> list[Finding]: ...


@contextmanager
def stream_findings(callback: Callable[[Finding], None] | None) -> Iterator[None]:
    """Stream findings created in one worker thread to live persistence."""
    previous = getattr(_finding_stream, "callback", None)
    _finding_stream.callback = callback
    try:
        yield
    finally:
        _finding_stream.callback = previous


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


def _is_probably_text(resp: "HttpResponse") -> bool:
    content_type = (resp.headers or {}).get("content-type", "").lower()
    if any(marker in content_type for marker in ("octet-stream", "image/", "audio/", "video/", "zip", "gzip")):
        return False
    sample = resp.content[:512] if resp.content else b""
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    return True


def format_http_response(resp: "HttpResponse") -> str:
    """Build a full HTTP transcript (status + headers + body) for offline debugging."""
    method = (resp.method or "GET").upper()
    url = resp.url or ""
    lines = [
        f"{method} {url} HTTP/1.1",
        f"# status: {resp.status_code}",
        f"# elapsed: {float(resp.elapsed or 0.0):.3f}s",
    ]
    if resp.error:
        lines.append(f"# error: {resp.error}")
    if resp.redirected_from:
        lines.append(f"# redirected_from: {' -> '.join(resp.redirected_from)}")
    if resp.soft404:
        lines.append("# soft404: true")
    if resp.forbidden_but_exists:
        lines.append("# forbidden_but_exists: true")
    lines.append("")
    lines.append(f"HTTP/1.1 {resp.status_code}")
    for key, value in (resp.headers or {}).items():
        lines.append(f"{key}: {value}")
    lines.append("")
    if resp.content and not _is_probably_text(resp):
        lines.append(f"[binary body omitted: {len(resp.content)} bytes — see companion .bin file]")
    else:
        lines.append(resp.text or "")
    if not lines[-1].endswith("\n"):
        return "\n".join(lines) + "\n"
    return "\n".join(lines)


def save_http_response(ctx: ScanContext, name: str, resp: "HttpResponse") -> str:
    """
    Persist the full HTTP response for a vuln/hit.

    Writes:
      - ``{host}_{name}.http`` — request line, status, headers, body (text)
      - ``{host}_{name}.bin`` — raw bytes when the body looks binary
      - ``{host}_{name}.txt`` — raw text body companion for quick grepping
    Returns the path to the ``.http`` transcript (used as ``raw_ref``).

    Evidence names are host-prefixed so concurrent targets probing the same
    path (e.g. ``/.git/config``, ``/.env``) do not clobber each other's bodies.
    """
    host = host_key(resp.url or "")
    keyed = f"{host}_{name}" if host else name
    http_path = save_evidence(ctx, keyed, format_http_response(resp), ext="http")
    if resp.content and not _is_probably_text(resp):
        save_evidence(ctx, keyed, resp.content, ext="bin")
    elif resp.text:
        save_evidence(ctx, keyed, resp.text, ext="txt")
    elif resp.content:
        save_evidence(ctx, keyed, resp.content, ext="bin")
    return http_path


def save_method_responses(
    ctx: ScanContext,
    name: str,
    url: str,
    results: Iterable["HttpResponse"],
) -> str:
    """
    Save every probed HTTP method response into a debug bundle.

    Layout:
      evidence/{name}/SUMMARY.txt
      evidence/{name}/GET.http
      evidence/{name}/PUT.http
      ...
    Returns the SUMMARY.txt path for ``raw_ref``.
    """
    evid_dir = Path(ctx.output_dir) / "evidence"
    bundle_dir = evid_dir / safe_filename(name)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    summary: list[str] = [
        f"URL: {url}",
        "METHOD\tSTATUS\tBYTES\tERROR\tFILE",
    ]
    for resp in results:
        method = (resp.method or "UNKNOWN").upper()
        # Keep override probes distinct when method stays POST.
        file_stem = method
        candidate = bundle_dir / f"{file_stem}.http"
        if candidate.exists():
            file_stem = f"{method}_{resp.status_code}"
            candidate = bundle_dir / f"{file_stem}.http"
            n = 2
            while candidate.exists():
                candidate = bundle_dir / f"{file_stem}_{n}.http"
                n += 1
        candidate.write_text(format_http_response(resp), encoding="utf-8", errors="ignore")
        if resp.content and not _is_probably_text(resp):
            (bundle_dir / f"{candidate.stem}.bin").write_bytes(resp.content)
        summary.append(
            f"{method}\t{resp.status_code}\t{len(resp.content or b'')}\t{resp.error or ''}\t{candidate.name}"
        )

    summary_path = bundle_dir / "SUMMARY.txt"
    summary_path.write_text("\n".join(summary) + "\n", encoding="utf-8")
    jsonl = Path(ctx.output_dir) / "evidence.jsonl"
    with jsonl.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"file": str(summary_path), "name": name, "bundle": str(bundle_dir)}) + "\n")
    return str(summary_path)


def body_extractions(ctx: ScanContext, url: str, body: str) -> dict:
    return extract_all(body, source_url=url, redact_values=ctx.config.redact_secrets)


_NON_SECRET_ENV_KEYS = {
    "path", "home", "pwd", "user", "shell", "shlvl", "term", "lang", "lc_all",
    "hostname", "host", "port", "node_version", "yarn_version", "npm_config_user_agent",
    "npm_config_cache", "colorterm", "editor", "pager", "tmpdir", "tmp", "temp",
    "logname", "mail", "oldpwd", "underscore", "_", "ps1", "ps2", "ls_colors",
    "xdg_runtime_dir", "xdg_session_id", "xdg_session_type", "display",
    "ssh_connection", "ssh_client", "ssh_tty", "debian_frontend",
}
_CRED_KEY_TOKENS = (
    "password", "passwd", "secret", "token", "apikey", "access_key", "private_key",
    "aws_access", "aws_secret", "akia", "asia", "smtp", "mail_pass", "mail_user",
    "database_url", "db_pass", "db_password", "credential", "bearer", "api_key",
)


def _looks_like_credential_line(value: str) -> bool:
    """Reject bash-history timestamps and other raw dump noise."""
    from app.core.result_secrets import is_noise_env_key

    text = (value or "").replace("\r", "").strip()
    if not text or len(text) < 6:
        return False
    if text.isdigit():
        return False
    if text.startswith("#") and text[1:].strip().isdigit():
        return False
    lowered = text.lower()
    # JS / source noise from next_config dumps.
    if any(token in lowered for token in ("process.env", "===", "=>", "const ", "let ", "function ")):
        return False
    if any(marker in lowered for marker in ("akia", "asia", "ghp_", "sk_live", "xox", "sg.")):
        return True
    if "=" not in text:
        return False
    key = text.split("=", 1)[0].strip().lower()
    if not key or key in _NON_SECRET_ENV_KEYS or is_noise_env_key(key):
        return False
    # Token match avoids ``pass`` matching ``private``.
    if any(token in key for token in _CRED_KEY_TOKENS):
        return True
    if key.endswith(("_key", "_secret", "_token", "_password", "_passwd")):
        return True
    return False


def exploit_lines_to_extracted(
    category: str,
    lines: list[Any],
    *,
    source_url: str = "",
) -> dict[str, Any]:
    """Normalize exploit extractor output into Results-compatible payloads.

    Only keep already-parsed secret/smtp dicts (or credential-looking lines).
    Raw bash_history / env dump lines are ignored — they inflate Results with
    timestamps and shell noise.
    """
    # API endpoint dumps are not credentials — skip *_apis categories.
    if category.endswith("_apis") or category in {"apis", "api"}:
        return {}
    secrets: list[dict[str, Any]] = []
    smtp: list[dict[str, Any]] = []
    kind_hint = (
        category.replace("_secrets", "")
        .replace("_smtp", "")
        or "env"
    )
    prefer_smtp = category.endswith("_smtp") or kind_hint == "smtp"
    api_kinds = {"absolute_api", "base_url", "fetch_call", "joomla_absolute_api"}
    for item in lines or []:
        if isinstance(item, dict):
            kind = str(item.get("kind") or ("smtp" if prefer_smtp else kind_hint))
            if kind in api_kinds:
                continue
            payload = {
                **item,
                "source_url": item.get("source_url") or source_url,
            }
            if kind == "smtp":
                smtp.append(payload)
            else:
                secrets.append(payload)
            continue
        if isinstance(item, str) and _looks_like_credential_line(item):
            secrets.append(
                {
                    "kind": kind_hint if kind_hint != "smtp" else "env",
                    "value": item.strip().replace("\r", ""),
                    "source_url": source_url,
                }
            )
    extracted: dict[str, Any] = {}
    if secrets:
        extracted["secrets"] = secrets
    if smtp:
        extracted["smtp"] = smtp
    return extracted


def append_exploit_secret_finding(
    *,
    findings: list[Finding],
    ctx: ScanContext,
    module: str,
    target: TargetContext,
    category: str,
    lines: list[Any],
    exploit_label: str,
    tags: list[str],
) -> None:
    extracted = exploit_lines_to_extracted(category, lines, source_url=target.url)
    secret_count = len(extracted.get("secrets") or []) + len(extracted.get("smtp") or [])
    if not secret_count:
        return
    preview: list[str] = []
    for item in (extracted.get("secrets") or []) + (extracted.get("smtp") or []):
        value = item.get("value")
        if isinstance(value, dict):
            preview.append(json.dumps(value, sort_keys=True))
        else:
            preview.append(str(value))
    findings.append(
        finding_from_hit(
            module=module,
            ftype="secrets",
            severity="high",
            target=target,
            url=target.url,
            title=f"Secret extraction: {category} ({exploit_label})",
            evidence="\n".join(preview[:20]),
            confidence=0.95,
            extracted=extracted,
            tags=[*tags, "secrets", category, "active-exploit"],
            validated=True,
        )
    )
    ctx.progress.add_hit(secrets=secret_count, module=module)


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
    finding = Finding(
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
    callback = getattr(_finding_stream, "callback", None)
    if callback:
        try:
            callback(finding)
        except Exception:
            # Live reporting must never interrupt the scanner module.
            pass
    return finding