"""Shared module helpers and ScanModule protocol."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterable, Iterator, Protocol, runtime_checkable

from app.extractors import extract_all
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import safe_filename

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
      - ``{name}.http`` — request line, status, headers, body (text)
      - ``{name}.bin`` — raw bytes when the body looks binary
      - ``{name}.txt`` — raw text body companion for quick grepping
    Returns the path to the ``.http`` transcript (used as ``raw_ref``).
    """
    http_path = save_evidence(ctx, name, format_http_response(resp), ext="http")
    if resp.content and not _is_probably_text(resp):
        save_evidence(ctx, name, resp.content, ext="bin")
    elif resp.text:
        save_evidence(ctx, name, resp.text, ext="txt")
    elif resp.content:
        save_evidence(ctx, name, resp.content, ext="bin")
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