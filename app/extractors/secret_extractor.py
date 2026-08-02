"""Secret / token extraction with parsers + regex packs."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from app.extractors import patterns as P
from app.extractors.validators import confidence_for, is_placeholder, looks_like_secret, redact
from app.utils.dedupe import value_hash


def _parse_env(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in P.ENV_LINE.finditer(text or ""):
        k, v = m.group(1), m.group(2).strip()
        if k and v and not is_placeholder(v):
            out[k] = v
    return out


def _parse_jsonish(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    if not text:
        return {}
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    # crude JS object -> json
    if text.startswith("{") and text.endswith("}"):
        candidate = re.sub(r"([,{]\s*)([A-Za-z_][\w]*)\s*:", r'\1"\2":', text)
        candidate = candidate.replace("'", '"')
        try:
            data = json.loads(candidate)
            if isinstance(data, dict):
                return data
        except Exception:
            return {}
    return {}


# Common manifest/package/meta fields that read as long, high-entropy strings
# but are public by design (site names, descriptions, PWA/app metadata, shader
# code assignments picked up by the bare KEY=VALUE line parser).
_NON_SECRET_KEYS = {
    "name", "short_name", "description", "orientation", "start_url", "scope",
    "display", "background_color", "theme_color", "lang", "dir", "id",
    "categories", "icons", "screenshots", "related_applications",
    "prefer_related_applications", "gcm_sender_id", "version", "author",
    "homepage", "license", "keywords", "main", "module", "exports", "browser",
    "style", "type", "sideeffects", "dependencies", "devdependencies",
    "peerdependencies", "scripts", "engines", "repository", "title", "alt",
    "label", "placeholder", "tooltip", "class", "classname", "role",
}


def _looks_like_sentence_or_code(value: str) -> bool:
    """Reject natural-language text and JS/GLSL statements, not credentials."""
    words = value.split()
    if len(words) >= 3:
        return True
    return bool(re.search(r"[(){};]|=>|function\s*\(", value))


def _interesting_kv(key: str, value: str) -> bool:
    key_l = key.strip().lower()
    if key_l in _NON_SECRET_KEYS or _looks_like_sentence_or_code(value):
        return False
    markers = (
        "key", "token", "secret", "password", "passwd", "auth", "api",
        "smtp", "mail", "aws", "private", "credential", "bearer",
    )
    # Bare KEY=VALUE / JSON fields only carry a credential when the key name
    # itself signals one; unconstrained entropy checks flag ordinary strings.
    return any(m in key_l for m in markers) and (looks_like_secret(value, min_len=6) or len(value) >= 8)


def extract_secrets(text: str, source_url: str = "", redact_values: bool = True) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    text = text or ""

    def add(kind: str, value: str, evidence: str = "", conf: float | None = None) -> None:
        value = (value or "").strip().strip("'\"")
        if not value or is_placeholder(value):
            return
        if kind.startswith("generic") and not looks_like_secret(value):
            return
        h = value_hash(f"{kind}:{value}:{source_url}")
        if h in seen:
            return
        seen.add(h)
        display = redact(value) if redact_values else value
        findings.append(
            {
                "kind": kind,
                "value": display,
                "value_hash": value_hash(value),
                "evidence": evidence[:240],
                "confidence": conf if conf is not None else confidence_for(kind, value, bool(evidence)),
                "source_url": source_url,
            }
        )

    # Parser pass: env + json
    env = _parse_env(text)
    for k, v in env.items():
        if _interesting_kv(k, v):
            add("env", f"{k}={v}", evidence=f"{k}=***")

    data = _parse_jsonish(text)
    if data:
        for k, v in data.items():
            if isinstance(v, (str, int, float)) and _interesting_kv(str(k), str(v)):
                add("env", f"{k}={v}", evidence=f"{k}=***")

    # Regex packs
    for _, pack in P.PATTERN_PACKS.items():
        for kind, regex in pack:
            for m in regex.finditer(text):
                val = P.first_group(m)
                add(kind, val, evidence=P.context_window(text, m.start(), m.end()))

    # Azure connection string
    for m in P.AZURE_STORAGE.finditer(text):
        add("azure_storage", m.group(0), evidence=P.context_window(text, m.start(), m.end()), conf=0.9)

    # Postmark
    for m in P.POSTMARK_TOKEN.finditer(text):
        add("postmark", m.group("token"), evidence=P.context_window(text, m.start(), m.end()), conf=0.9)

    # Twilio SID + nearby auth
    sids = list(P.TWILIO_SID.finditer(text))
    auths = list(P.TWILIO_AUTH.finditer(text))
    for sm in sids:
        sid = sm.group(1)
        nearby = text[max(0, sm.start() - 200) : sm.end() + 200]
        auth_m = P.TWILIO_AUTH.search(nearby) or (auths[0] if auths else None)
        if auth_m:
            add("twilio", f"{sid}|{auth_m.group(1)}", evidence=P.context_window(text, sm.start(), sm.end()), conf=0.9)
        else:
            add("twilio_sid", sid, evidence=P.context_window(text, sm.start(), sm.end()), conf=0.7)

    # Twilio base64
    for m in P.TWILIO_B64.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0)).decode("utf-8", errors="ignore")
            if ":" in decoded:
                sid, token = decoded.split(":", 1)
                if sid.startswith("AC") and len(token) == 32:
                    add("twilio_b64", f"{sid}|{token}", evidence=m.group(0)[:40] + "...", conf=0.9)
        except Exception:
            continue

    # AWS access + nearby secret as one ``access:secret`` value.
    for am in P.AWS_ACCESS_KEY.finditer(text):
        ak = am.group(1)
        window = text[max(0, am.start() - 300) : am.end() + 300]
        secrets = P.AWS_SECRET_KEY.findall(window)
        paired = False
        for sk in secrets:
            if re.search(r"[A-Z]", sk) and re.search(r"[0-9]", sk):
                add("aws_cred", f"{ak}:{sk}", evidence=P.context_window(text, am.start(), am.end()), conf=0.92)
                paired = True
        if not paired:
            add("aws_access_key", ak, evidence=P.context_window(text, am.start(), am.end()), conf=0.88)

    return findings