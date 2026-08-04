"""Focused extraction filters for WordPress / Joomla CMS modules."""

from __future__ import annotations

import re
from typing import Any

from app.extractors import extract_all
from app.extractors.joomla_api_extractor import extract_joomla_apis
from app.storage.models import ScanContext

CMS_BLOCKED_SECRET_KINDS = frozenset(
    {
        "generic_api_key",
        "jwt",
        "google_api",
        "bearer",
        "openai",
        "anthropic",
        "tencent",
        "aliyun",
        "azure_storage",
        "slack",
        "joomla_bearer",
        "joomla_api_key",
        "jconfig_secret",
        "jconfig_password",
        "jconfig_dbpassword",
        "jconfig_user",
        "jconfig_db",
        "jconfig_dbprefix",
        "jconfig_host",
        "jconfig_oauthclientid",
        "jconfig_oauthclientsecret",
        "jconfig_api_key",
        "jconfig_apikey",
        "jconfig_access_token",
    }
)

CMS_ENV_KEY_ALLOW = re.compile(
    r"(?i)(smtp|mail|aws|stripe|sendgrid|brevo|github|gitlab|twilio|mailgun|postmark|xsmtp)"
)

CMS_JCONFIG_SECRET_ALLOW = frozenset({"jconfig_smtppass", "jconfig_smtpuser"})


def _env_key_allowed(value: str) -> bool:
    if "=" not in value:
        return False
    key = value.split("=", 1)[0].strip()
    return bool(CMS_ENV_KEY_ALLOW.search(key))


def filter_cms_secret(item: dict[str, Any]) -> bool:
    kind = str(item.get("kind") or "").lower()
    if kind in CMS_BLOCKED_SECRET_KINDS:
        return False
    if kind.startswith("jconfig_") and kind not in CMS_JCONFIG_SECRET_ALLOW:
        return False
    if kind == "env" and not _env_key_allowed(str(item.get("value") or "")):
        return False
    return True


def filter_cms_smtp(item: dict[str, Any]) -> bool:
    value = item.get("value")
    if not isinstance(value, dict):
        return False
    host = str(value.get("host") or "").strip()
    user = str(value.get("user") or "").strip()
    password = str(value.get("pass") or "").strip()
    # Prefer complete credentials; host-only / user-only rows are noise.
    if not password:
        return False
    if not host and not user:
        return False
    return True


def filter_cms_extractions(extracted: dict[str, Any]) -> dict[str, Any]:
    secrets = [item for item in extracted.get("secrets") or [] if filter_cms_secret(item)]
    smtp = [item for item in extracted.get("smtp") or [] if filter_cms_smtp(item)]
    return {
        "secrets": secrets,
        "smtp": smtp,
        "apis": [],
        "endpoints": [],
    }


def cms_body_extractions(ctx: ScanContext, url: str, body: str, *, joomla: bool = False) -> dict[str, Any]:
    base = extract_all(body, source_url=url, redact_values=ctx.config.redact_secrets)
    if joomla:
        joomla_part = extract_joomla_apis(body, source_url=url, redact_values=ctx.config.redact_secrets)
        merged = {
            "secrets": [*base.get("secrets", []), *joomla_part.get("secrets", [])],
            "smtp": base.get("smtp", []),
            "apis": [],
            "endpoints": [],
        }
        return filter_cms_extractions(merged)
    return filter_cms_extractions(base)
