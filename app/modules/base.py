"""Shared module helpers and ScanModule protocol."""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Protocol, runtime_checkable

from app.extractors import extract_all
from app.storage.models import Finding, ScanContext, TargetContext
from app.utils.normalize import safe_filename

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