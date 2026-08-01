"""API endpoint and baseURL extraction."""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

from app.extractors import patterns as P
from app.extractors.validators import confidence_for, is_interesting_url, is_placeholder
from app.utils.dedupe import value_hash


def extract_apis(text: str, source_url: str = "") -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    text = text or ""

    def add(kind: str, value: str, evidence: str = "", conf: float | None = None) -> None:
        value = (value or "").strip().rstrip("\\")
        if not value or is_placeholder(value):
            return
        if value.startswith("http") and not is_interesting_url(value):
            return
        # skip static assets
        low = value.lower()
        if any(low.endswith(ext) for ext in (".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".ico")):
            return
        h = value_hash(f"{kind}:{value}:{source_url}")
        if h in seen:
            return
        seen.add(h)
        findings.append(
            {
                "kind": kind,
                "value": value,
                "value_hash": value_hash(value),
                "evidence": evidence[:240],
                "confidence": conf if conf is not None else confidence_for("api_endpoint", value, True),
                "source_url": source_url,
            }
        )

    for m in P.ABS_URL.finditer(text):
        url = m.group(0).rstrip(").,;'\"")
        path = urlparse(url).path.lower()
        if any(x in path for x in ("/api", "/graphql", "/v1", "/v2", "/oauth", "/auth", "/webhook")):
            add("absolute_api", url, evidence=P.context_window(text, m.start(), m.end()), conf=0.75)
        elif any(x in url.lower() for x in ("api.", "graph.", "backend.", "gateway.")):
            add("absolute_api", url, evidence=P.context_window(text, m.start(), m.end()), conf=0.7)

    for m in P.API_PATH.finditer(text):
        path = m.group(1)
        full = urljoin(source_url, path) if source_url else path
        add("api_path", full, evidence=P.context_window(text, m.start(), m.end()), conf=0.8)

    for m in P.GRAPHQL.finditer(text):
        path = m.group(1)
        full = urljoin(source_url, path) if source_url else path
        add("graphql", full, evidence=P.context_window(text, m.start(), m.end()), conf=0.85)

    for m in P.FETCH_URL.finditer(text):
        val = m.group(1)
        if val.startswith("/") or val.startswith("http"):
            full = urljoin(source_url, val) if source_url and val.startswith("/") else val
            add("fetch_call", full, evidence=P.context_window(text, m.start(), m.end()), conf=0.7)

    for m in P.BASE_URL_ASSIGN.finditer(text):
        add("base_url", m.group(1), evidence=P.context_window(text, m.start(), m.end()), conf=0.8)

    return findings