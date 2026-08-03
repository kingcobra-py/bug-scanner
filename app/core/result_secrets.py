"""Normalize / dedupe credential rows for the Results dashboard."""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from app.core.providers import provider_for_kind
from app.extractors.patterns import IGNORED_SECRET_KINDS
from app.extractors.validators import (
    is_placeholder,
    is_useless_env_assignment,
    looks_like_js_expression,
)

_AWS_KEY_RE = re.compile(r"^(?:AKIA|ASIA|ABIA|ANPA)[0-9A-Z]{12,}$")
_AWS_SECRET_RE = re.compile(r"^[A-Za-z0-9/+=]{30,}$")
_SMTP_PLACEHOLDER_USERS = frozenset({"apikey", "api_key", "resend"})
_API_NOISE_KINDS = frozenset({"absolute_api", "base_url", "fetch_call", "joomla_absolute_api"})

_NOISE_ENV_EXACT = frozenset({
    "aws_execution_env", "aws_region", "aws_default_region", "aws_app_env",
    "aws_role_arn", "aws_web_identity_token_file", "aws_sts_regional_endpoints",
    "aws_session_token", "hostname", "node_version", "yarn_version", "port",
    "home", "path", "pwd", "shlvl", "next_deployment_id",
})
_NOISE_ENV_PREFIXES = (
    "__next_private_",
    "aws_lambda_",
    "aws_container_",
    "npm_",
    "kubernetes_",
    "website_",
    "ecs_",
)
_SMTP_ENV_KEYS = {
    "host": {"host", "hostname", "server", "smtp_host", "mail_host", "email_host"},
    "port": {"port", "smtp_port", "mail_port", "email_port"},
    "user": {
        "user", "username", "user_name", "smtp_user", "smtp_username", "smtp_email",
        "mail_user", "mail_username", "email_user", "email_username", "from",
    },
    "pass": {
        "pass", "password", "passwd", "pass_word", "smtp_pass", "smtp_password",
        "mail_pass", "mail_password", "email_pass", "email_password",
    },
}


def _clean(value: str) -> str:
    text = (value or "").replace("\r", "").replace("\n", "")
    text = text.replace("\\r", "").replace("\\n", "")
    return text.strip().strip("'\"")


def _env_parts(value: str) -> tuple[str, str] | None:
    raw = _clean(value)
    if "=" not in raw:
        return None
    key, rhs = raw.split("=", 1)
    key = key.strip()
    rhs = _clean(rhs)
    # Unwrap glued dumps: __NEXT_PRIVATE_RUNTIME_TYPE=MAILGUN_API_KEY=xxx
    while "=" in rhs:
        nested_key, nested_val = rhs.split("=", 1)
        nested_key = nested_key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", nested_key):
            break
        key, rhs = nested_key, _clean(nested_val)
    if not key:
        return None
    return key, rhs


def is_noise_env_key(key: str) -> bool:
    key_l = (key or "").strip().lower()
    if not key_l:
        return True
    if key_l in _NOISE_ENV_EXACT:
        return True
    if any(key_l.startswith(prefix) for prefix in _NOISE_ENV_PREFIXES):
        return True
    if key_l.startswith("next_public_") and "secret" not in key_l and "private" not in key_l:
        return True
    return False


def _smtp_field(key: str) -> str | None:
    key_l = key.strip().lower()
    if key_l.startswith("appsetting_"):
        key_l = key_l[len("appsetting_") :]
    for prefix in ("smtp_", "mail_", "email_"):
        if key_l.startswith(prefix):
            key_l = key_l[len(prefix) :]
            break
    else:
        return None
    for field, aliases in _SMTP_ENV_KEYS.items():
        if key_l in aliases:
            return field
    return None


def _is_useless_result(kind: str, value: str) -> bool:
    kind_l = (kind or "").lower()
    value_s = _clean(value)
    if kind_l in IGNORED_SECRET_KINDS or kind_l.startswith("generic"):
        return True
    if kind_l in _API_NOISE_KINDS:
        return True
    if value_s.isdigit():
        return True
    if value_s.startswith("AIza"):
        return True
    if value_s.startswith("eyJ") and value_s.count(".") >= 2:
        return True
    if "google_api" in kind_l or kind_l == "jwt":
        return True
    if kind_l == "env":
        parts = _env_parts(value_s)
        if parts and is_noise_env_key(parts[0]):
            return True
        if is_useless_env_assignment(value_s):
            return True
    rhs = value_s.split("=", 1)[1] if kind_l == "env" and "=" in value_s else value_s
    if looks_like_js_expression(rhs) or is_placeholder(rhs):
        return True
    return False


def normalize_result_secrets(secrets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Pair AWS/SMTP credentials and strip dashboard noise."""
    aws_by_source: dict[str, dict[str, str]] = defaultdict(dict)
    smtp_by_source: dict[str, dict[str, str]] = defaultdict(dict)
    kept: list[dict[str, Any]] = []

    for item in secrets:
        kind = str(item.get("kind") or "")
        value = item.get("value")
        source = str(item.get("source_url") or "")

        if kind in _API_NOISE_KINDS:
            continue

        if kind == "smtp" and isinstance(value, dict):
            host = _clean(str(value.get("host") or ""))
            port = _clean(str(value.get("port") or ""))
            user = _clean(str(value.get("user") or ""))
            password = _clean(str(value.get("pass") or value.get("password") or ""))
            if is_placeholder(password):
                continue
            if user and is_placeholder(user) and user.lower() not in _SMTP_PLACEHOLDER_USERS:
                user = ""
            if not password:
                continue
            bucket = smtp_by_source[source or host or user]
            if host:
                bucket["host"] = host
            if port:
                bucket["port"] = port
            if user:
                bucket["user"] = user
            if password:
                bucket["pass"] = password
            bucket.setdefault("_meta", item)
            continue

        display = _clean(str(value or ""))
        if not display:
            continue

        if kind == "env" or (kind in {"exploit", "dotenv", "bash_history"} and "=" in display):
            parts = _env_parts(display)
            if not parts:
                continue
            key, rhs = parts
            key_l = key.lower()

            if is_noise_env_key(key):
                # Recover nested credential from glued Next runtime dumps.
                nested = _env_parts(f"{key}={rhs}")
                if nested and nested[0].lower() != key_l and not is_noise_env_key(nested[0]):
                    key, rhs = nested
                    key_l = key.lower()
                    display = f"{key}={rhs}"
                else:
                    continue

            smtp_field = _smtp_field(key)
            if smtp_field:
                if smtp_field in {"user", "pass"} and is_placeholder(rhs):
                    continue
                bucket = smtp_by_source[source or ""]
                bucket[smtp_field] = rhs
                bucket.setdefault("_meta", item)
                continue

            if key_l in {"aws_access_key_id", "aws_access_key"}:
                if _AWS_KEY_RE.match(rhs):
                    aws_by_source[source]["access"] = rhs
                    aws_by_source[source].setdefault("_meta", item)
                # Drop non-key leftovers like AWS_ACCESS_KEY_ID=user-prod-bucket.
                continue
            if key_l in {"aws_secret_access_key", "aws_secret_key"}:
                if _AWS_SECRET_RE.match(rhs) or (
                    len(rhs) >= 20 and re.search(r"[A-Za-z]", rhs) and re.search(r"[0-9/+=]", rhs)
                ):
                    aws_by_source[source]["secret"] = rhs
                    aws_by_source[source].setdefault("_meta", item)
                    continue
                # Odd/short secret values still surface as env rows.
            if key_l == "aws_session_token":
                # Useful for exploit context but too noisy/huge for Results.
                continue
            # Recipient / from-only mail fields are not credentials.
            if key_l.endswith(("_to", "_from", "_cc", "_bcc")) or key_l in {"smtp_email", "mail_from", "email_from"}:
                continue

            display = f"{key}={rhs}"
            if is_useless_env_assignment(display) or _is_useless_result("env", display):
                continue
            kept.append({**item, "kind": "env", "value": display})
            continue

        if kind == "aws_access_key":
            if _AWS_KEY_RE.match(display):
                aws_by_source[source]["access"] = display
                aws_by_source[source].setdefault("_meta", item)
            continue

        if kind == "aws_cred":
            if "|" in display:
                left, right = display.split("|", 1)
                if left.startswith(("AKIA", "ASIA", "ABIA", "ANPA")) and right:
                    display = f"{left}:{right}"
            if ":" in display:
                left, right = display.split(":", 1)
                if left.startswith(("AKIA", "ASIA", "ABIA", "ANPA")) and right:
                    aws_by_source[source]["access"] = left
                    aws_by_source[source]["secret"] = right
                    aws_by_source[source].setdefault("_meta", item)
                    continue

        if _is_useless_result(kind, display):
            continue
        kept.append({**item, "kind": kind, "value": display})

    paired_access: set[str] = set()
    for source, bucket in aws_by_source.items():
        access = bucket.get("access") or ""
        secret = bucket.get("secret") or ""
        meta = bucket.get("_meta") or {"provider": "aws", "source_url": source, "occurrences": 1}
        # Only emit AWS when both access + secret are present.
        # Bare ASIA/AKIA from presigned URLs / HTML are not usable credentials.
        if access and secret:
            paired_access.add(access)
            kept.append(
                {
                    **meta,
                    "kind": "aws_cred",
                    "provider": "aws",
                    "value": f"{access}:{secret}",
                    "source_url": source or meta.get("source_url") or "",
                }
            )

    for source, bucket in smtp_by_source.items():
        host = bucket.get("host") or ""
        port = bucket.get("port") or ""
        user = bucket.get("user") or ""
        password = bucket.get("pass") or ""
        if is_placeholder(password):
            continue
        if user and is_placeholder(user) and user.lower() not in _SMTP_PLACEHOLDER_USERS:
            user = ""
        # Results only keeps SMTP rows with a real password + identity.
        if not password or (not host and not user):
            continue
        # Password-looking blobs without host/user were already rejected; also
        # reject clearly non-host identities like bare "email_user".
        if not host and user and "@" not in user and user.lower() not in _SMTP_PLACEHOLDER_USERS:
            continue
        host_part = f"{host}:{port}" if host and port else host
        parts = [part for part in (host_part, user, password) if part]
        meta = bucket.get("_meta") or {"provider": "smtp", "source_url": source, "occurrences": 1}
        provider = provider_for_kind(host) if host else "smtp"
        if provider == "other":
            provider = "smtp"
        kept.append(
            {
                **meta,
                "kind": "smtp",
                "provider": provider,
                "value": " | ".join(parts),
                "source_url": source or meta.get("source_url") or "",
            }
        )

    # Drop bare access keys (paired or not), and dedupe values.
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in kept:
        kind = str(item.get("kind") or "")
        value = str(item.get("value") or "")
        if kind == "aws_access_key":
            continue
        if kind == "aws_cred" and ":" in value:
            paired_access.add(value.split(":", 1)[0])
        dedupe = f"{item.get('provider') or provider_for_kind(kind)}:{kind}:{value}"
        if dedupe in seen:
            # Keep higher occurrence count when present.
            for existing in out:
                if f"{existing.get('provider')}:{existing.get('kind')}:{existing.get('value')}" == dedupe:
                    existing["occurrences"] = max(
                        int(existing.get("occurrences") or 1),
                        int(item.get("occurrences") or 1),
                    )
                    src = item.get("source_url") or ""
                    sources = existing.setdefault("sources", [])
                    if src and src not in sources:
                        sources.append(src)
                    break
            continue
        seen.add(dedupe)
        item.setdefault("provider", provider_for_kind(kind))
        out.append(item)
    return out
