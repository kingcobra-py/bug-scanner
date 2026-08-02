"""Focused secret packs for Joomla / WordPress modules."""

from __future__ import annotations

import re
from typing import Any

from app.extractors import patterns as P
from app.extractors.validators import confidence_for, is_placeholder, redact
from app.utils.dedupe import value_hash

# Explicit allowlist — nothing outside this set is reported.
# AWS access keys are handled below so they can be paired with a nearby
# secret as a single ``access:secret`` value instead of two separate rows.
PRIORITY_PACKS: dict[str, list[tuple[str, re.Pattern]]] = {
    "github_token": [("github_token", P.GITHUB_TOKEN)],
    "stripe": [("stripe_live", P.STRIPE_LIVE), ("stripe_test", P.STRIPE_TEST)],
    "sendgrid": [("sendgrid", P.SENDGRID_KEY)],
    "brevo": [("brevo", P.BREVO_KEY), ("xsmtp", P.XSMTP_KEY)],
}


def extract_priority_secrets(
    text: str,
    source_url: str = "",
    *,
    redact_values: bool = True,
) -> list[dict[str, Any]]:
    """Extract only AWS, GitHub, Stripe, SendGrid, and Brevo secrets."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    text = text or ""

    def add(kind: str, value: str, evidence: str = "", conf: float | None = None) -> None:
        value = (value or "").strip().strip("'\"")
        if not value or is_placeholder(value):
            return
        key = value_hash(f"priority:{kind}:{value}:{source_url}")
        if key in seen:
            return
        seen.add(key)
        findings.append(
            {
                "kind": kind,
                "value": redact(value) if redact_values else value,
                "value_hash": value_hash(value),
                "evidence": evidence[:240],
                "confidence": conf if conf is not None else confidence_for(kind, value, bool(evidence)),
                "source_url": source_url,
                "extractor": "priority_secrets",
            }
        )

    for _, pack in PRIORITY_PACKS.items():
        for kind, regex in pack:
            for match in regex.finditer(text):
                add(kind, P.first_group(match), evidence=P.context_window(text, match.start(), match.end()))

    # Pair AWS access keys with nearby secrets as one value:
    # ``AKIA...:wJal...`` (not two separate rows).
    for access_match in P.AWS_ACCESS_KEY.finditer(text):
        access_key = access_match.group(1)
        window = text[max(0, access_match.start() - 300) : access_match.end() + 300]
        paired = False
        for secret in P.AWS_SECRET_KEY.findall(window):
            if re.search(r"[A-Z]", secret) and re.search(r"[0-9]", secret):
                add(
                    "aws_cred",
                    f"{access_key}:{secret}",
                    evidence=P.context_window(text, access_match.start(), access_match.end()),
                    conf=0.92,
                )
                paired = True
        if not paired:
            add(
                "aws_access_key",
                access_key,
                evidence=P.context_window(text, access_match.start(), access_match.end()),
                conf=0.88,
            )

    return findings


def priority_extractions(text: str, source_url: str = "", *, redact_values: bool = True) -> dict[str, list[Any]]:
    secrets = extract_priority_secrets(text, source_url=source_url, redact_values=redact_values)
    return {
        "secrets": secrets,
        "apis": [],
        "smtp": [],
        "endpoints": [],
        "extractor": "priority_secrets",
    }
