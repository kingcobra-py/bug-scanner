"""Extraction facade combining secrets, APIs, and SMTP."""

from __future__ import annotations

from typing import Any

from app.extractors.api_extractor import extract_apis
from app.extractors.secret_extractor import extract_secrets
from app.extractors.smtp_extractor import extract_smtp


def extract_all(text: str, source_url: str = "", redact_values: bool = True) -> dict[str, list[Any]]:
    secrets = extract_secrets(text, source_url=source_url, redact_values=redact_values)
    apis = extract_apis(text, source_url=source_url)
    smtp = extract_smtp(text, source_url=source_url, redact_values=redact_values)
    return {
        "secrets": secrets,
        "apis": apis,
        "smtp": smtp,
        "endpoints": [a["value"] for a in apis if a.get("value")],
    }
