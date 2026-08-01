"""Joomla-specific API / credential pattern extraction (GET body parsing only)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

from app.extractors.validators import confidence_for, is_placeholder, looks_like_secret, redact
from app.utils.dedupe import value_hash

# Joomla Web Services / component API surfaces
JOOMLA_API_PATH = re.compile(
    r"""(?ix)
    (?:
        ['"](?P<qpath>/api/index\.php/v\d+/[A-Za-z0-9_\-./{}]+)['"]
      | (?P<path>/api/index\.php/v\d+/[A-Za-z0-9_\-./{}]+)
      | ['"](?P<com>/index\.php\?option=com_[A-Za-z0-9_]+(?:&(?:task|view|format)=[A-Za-z0-9_.\-]+)*)['"]
      | (?P<ajax>/component/ajax/[A-Za-z0-9_\-./]+)
      | (?P<jce>/index\.php\?option=com_jce&task=[A-Za-z0-9_.]+)
    )
    """
)

JOOMLA_ABS_API = re.compile(
    r"""(?ix)
    https?://[^\s\"'<>\\]+?
    (?:
        /api/index\.php/v\d+/[A-Za-z0-9_\-./{}]+
      | /index\.php\?option=com_[A-Za-z0-9_]+
      | /component/ajax/[A-Za-z0-9_\-./]+
    )
    """
)

JOOMLA_ROUTES_JSON = re.compile(
    r"""(?ix)
    ["'](?:routes|namespaces|links)["']\s*:\s*\[([^\]]{0,2000})\]
    """
)

JOOMLA_ROUTE_ITEM = re.compile(
    r"""(?ix)
    ["'](/?(?:api/)?[A-Za-z0-9_\-./{}]+)["']
    """
)

# JConfig / configuration.php credential + API-adjacent fields
JCONFIG_ASSIGN = re.compile(
    r"""(?ix)
    (?:public\s+)?\$(?P<key>
        secret|db|dbprefix|user|password|dbpassword|host|mailfrom|fromname|
        smtphost|smtpuser|smtppass|smtpport|smtpsecure|mailer|
        live_site|oauthClientId|oauthClientSecret|api_key|apikey|access_token
    )\s*=\s*['"](?P<value>[^'"]+)['"]
    """
)

JOOMLA_BEARER = re.compile(
    r"""(?ix)
    (?:authorization|X-Joomla-Token|joomla[_-]?token|api[_-]?token)\s*[:=]\s*['"]?(?:Bearer\s+)?([A-Za-z0-9\-_\.=]{16,})['"]?
    """
)

JOOMLA_GENERIC_KEY = re.compile(
    r"""(?ix)
    (?:
        ["']?(?:api[_-]?key|client[_-]?secret|access[_-]?token|oauth[_-]?token|webhook[_-]?secret)["']?
        \s*[:=]\s*
        ["']([A-Za-z0-9_\-\.=]{16,})["']
    )
    """
)

INTERESTING_JCONFIG = {
    "secret",
    "password",
    "dbpassword",
    "smtppass",
    "oauthclientsecret",
    "api_key",
    "apikey",
    "access_token",
}


def extract_joomla_apis(
    text: str,
    source_url: str = "",
    *,
    redact_values: bool = True,
) -> dict[str, list[dict[str, Any]]]:
    text = text or ""
    apis: list[dict[str, Any]] = []
    secrets: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_api(kind: str, value: str, evidence: str = "", conf: float = 0.8) -> None:
        value = (value or "").strip().rstrip("\\).,;'\"")
        if not value or is_placeholder(value):
            return
        key = value_hash(f"joomla-api:{kind}:{value}:{source_url}")
        if key in seen:
            return
        seen.add(key)
        full = urljoin(source_url, value) if source_url and value.startswith("/") else value
        apis.append(
            {
                "kind": kind,
                "value": full,
                "value_hash": value_hash(full),
                "evidence": evidence[:240],
                "confidence": conf,
                "source_url": source_url,
                "extractor": "joomla",
            }
        )

    def add_secret(kind: str, value: str, evidence: str = "", conf: float | None = None) -> None:
        value = (value or "").strip().strip("'\"")
        if not value or is_placeholder(value):
            return
        if not looks_like_secret(value) and kind not in {"jconfig_secret", "jconfig_password", "jconfig_dbpassword"}:
            if len(value) < 8:
                return
        key = value_hash(f"joomla-secret:{kind}:{value}:{source_url}")
        if key in seen:
            return
        seen.add(key)
        secrets.append(
            {
                "kind": kind,
                "value": redact(value) if redact_values else value,
                "value_hash": value_hash(value),
                "evidence": evidence[:240],
                "confidence": conf if conf is not None else confidence_for(kind, value, True),
                "source_url": source_url,
                "extractor": "joomla",
            }
        )

    for match in JOOMLA_API_PATH.finditer(text):
        value = next((g for g in match.groups() if g), "")
        if value:
            add_api("joomla_api_path", value, evidence=match.group(0)[:240], conf=0.88)

    for match in JOOMLA_ABS_API.finditer(text):
        add_api("joomla_absolute_api", match.group(0), evidence=match.group(0)[:240], conf=0.85)

    for match in JOOMLA_ROUTES_JSON.finditer(text):
        blob = match.group(1) or ""
        for item in JOOMLA_ROUTE_ITEM.finditer(blob):
            route = item.group(1)
            if route and ("api" in route.lower() or "/" in route):
                add_api("joomla_route", route, evidence=match.group(0)[:240], conf=0.8)

    for match in JCONFIG_ASSIGN.finditer(text):
        key = (match.group("key") or "").lower()
        value = match.group("value") or ""
        if key in INTERESTING_JCONFIG or "pass" in key or "secret" in key or "token" in key or "key" in key:
            add_secret(f"jconfig_{key}", value, evidence=f"${key}=***", conf=0.95)
        if key in {"live_site", "smtphost", "mailfrom"} and value:
            add_api(f"jconfig_{key}", value, evidence=match.group(0)[:240], conf=0.7)

    for match in JOOMLA_BEARER.finditer(text):
        add_secret("joomla_bearer", match.group(1), evidence=match.group(0)[:240], conf=0.85)

    for match in JOOMLA_GENERIC_KEY.finditer(text):
        add_secret("joomla_api_key", match.group(1), evidence=match.group(0)[:240], conf=0.8)

    return {"apis": apis, "secrets": secrets, "endpoints": [a["value"] for a in apis]}
