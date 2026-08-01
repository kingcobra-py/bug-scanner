"""Deterministic dedupe helpers for findings and values."""

from __future__ import annotations

import hashlib
from typing import Any, Iterable


def value_hash(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8", errors="ignore")).hexdigest()[:16]


def finding_id(ftype: str, target: str, url: str, title: str, value: str = "") -> str:
    raw = f"{ftype}|{target}|{url}|{title}|{value_hash(value)}"
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:32]


def dedupe_strings(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = (item or "").strip()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(key)
    return out


def dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for f in findings:
        fid = f.get("id") or finding_id(
            f.get("type", "other"),
            f.get("target", ""),
            f.get("url", ""),
            f.get("title", ""),
            str(f.get("extracted", {})),
        )
        if fid in seen:
            continue
        seen.add(fid)
        f["id"] = fid
        out.append(f)
    return out