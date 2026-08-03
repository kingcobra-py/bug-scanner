"""API/secret provider metadata used by result filters."""

from __future__ import annotations

import re
from typing import Any


PROVIDERS: dict[str, dict[str, str]] = {
    "aws": {"label": "AWS", "color": "#ff9900", "logo": "/static/img/providers/aws.svg"},
    "github": {"label": "GitHub", "color": "#f0f6fc", "logo": "/static/img/providers/github.svg"},
    "gitlab": {"label": "GitLab", "color": "#fc6d26", "logo": "https://cdn.simpleicons.org/gitlab/fc6d26"},
    "stripe": {"label": "Stripe", "color": "#635bff", "logo": "/static/img/providers/stripe.svg"},
    "sendgrid": {"label": "SendGrid", "color": "#1a82e2", "logo": "/static/img/providers/sendgrid.png"},
    "brevo": {"label": "Brevo", "color": "#0b996e", "logo": "/static/img/providers/brevo.svg"},
    "mailgun": {"label": "Mailgun", "color": "#f06b66", "logo": "/static/img/providers/mailgun.svg"},
    "postmark": {"label": "Postmark", "color": "#ffde00", "logo": "https://cdn.simpleicons.org/postmark/ffde00"},
    "slack": {"label": "Slack", "color": "#36c5f0", "logo": "https://cdn.simpleicons.org/slack/36c5f0"},
    "openai": {"label": "OpenAI", "color": "#10a37f", "logo": "https://cdn.simpleicons.org/openai/10a37f"},
    "anthropic": {"label": "Anthropic", "color": "#d4a27f", "logo": "https://cdn.simpleicons.org/anthropic/d4a27f"},
    "azure": {"label": "Azure", "color": "#0089d6", "logo": "/static/img/providers/azure.svg"},
    "twilio": {"label": "Twilio", "color": "#f22f46", "logo": "/static/img/providers/twilio.svg"},
    "tencent": {"label": "Tencent", "color": "#00a4ff", "logo": "https://cdn.simpleicons.org/tencentqq/00a4ff"},
    "aliyun": {"label": "Alibaba Cloud", "color": "#ff6a00", "logo": "https://cdn.simpleicons.org/alibabacloud/ff6a00"},
    "smtp": {"label": "SMTP", "color": "#22d3ee", "logo": ""},
    "other": {"label": "Other", "color": "#94a3b8", "logo": ""},
}

# Value-shape detectors used when reclassifying env KEY=VALUE rows.
# sk_test_ is intentionally omitted.
_VALUE_KIND_RULES: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("stripe", "stripe_live", re.compile(r"^sk_live_[0-9a-zA-Z]{24,}$")),
    ("brevo", "brevo", re.compile(r"^xkeysib-[A-Za-z0-9]{64}-[A-Za-z0-9]{16}$", re.I)),
    ("brevo", "xsmtp", re.compile(r"^xsmtpsib-[a-fA-F0-9]{64}-[A-Za-z0-9]{16}$", re.I)),
    ("sendgrid", "sendgrid", re.compile(r"^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$")),
    ("mailgun", "mailgun", re.compile(r"^key-[0-9a-zA-Z]{32}$")),
    ("github", "github_token", re.compile(
        r"^(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9]{36}$|^github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59}$"
    )),
    ("gitlab", "gitlab_token", re.compile(r"^glpat-[A-Za-z0-9_-]{20,}$")),
    ("slack", "slack", re.compile(r"^xox[baprs]-[0-9A-Za-z-]{10,}$")),
    ("openai", "openai", re.compile(r"^sk-[A-Za-z0-9]{20,}$")),
    ("anthropic", "anthropic", re.compile(r"^sk-ant-[A-Za-z0-9\-_]{20,}$")),
    ("twilio", "twilio_sid", re.compile(r"^AC[0-9a-fA-F]{32}$")),
)

# Low-value vendors we never promote into Results provider chips.
_IGNORED_ENV_PROVIDERS = frozenset({
    "paystack", "sanity", "emailjs", "nextauth", "msi",
})

# Env key prefixes / markers → provider (+ optional kind override).
_ENV_KEY_PROVIDERS: tuple[tuple[str, str, str | None], ...] = (
    ("stripe", "stripe", None),
    ("brevo", "brevo", "brevo"),
    ("sendinblue", "brevo", "brevo"),
    ("sendgrid", "sendgrid", "sendgrid"),
    ("mailgun", "mailgun", "mailgun"),
    ("postmark", "postmark", "postmark"),
    ("twilio", "twilio", "twilio"),
    ("openai", "openai", "openai"),
    ("anthropic", "anthropic", "anthropic"),
    ("github", "github", "github_token"),
    ("gitlab", "gitlab", "gitlab_token"),
    ("slack", "slack", "slack"),
    ("azure", "azure", "azure"),
    ("aws", "aws", None),
)


def provider_for_kind(kind: str) -> str:
    value = (kind or "").lower()
    rules = (
        ("aws", ("aws", "amazon", "ses")),
        ("github", ("github",)),
        ("gitlab", ("gitlab",)),
        ("stripe", ("stripe",)),
        ("sendgrid", ("sendgrid",)),
        ("brevo", ("brevo", "sib", "xsmtp")),
        ("mailgun", ("mailgun",)),
        ("postmark", ("postmark",)),
        ("slack", ("slack",)),
        ("openai", ("openai",)),
        ("anthropic", ("anthropic",)),
        ("azure", ("azure",)),
        ("twilio", ("twilio",)),
        ("tencent", ("tencent",)),
        ("aliyun", ("aliyun", "alibaba")),
        ("smtp", ("smtp", "mail_", "mail-")),
    )
    for provider, markers in rules:
        if any(marker in value for marker in markers):
            return provider
    return "other"


def classify_env_assignment(key: str, value: str) -> tuple[str, str, str] | None:
    """Map ``KEY=VALUE`` into ``(provider, kind, display_value)`` when known.

    Returns None when the assignment should stay as a generic ``env`` row (or be
    filtered elsewhere). Known SaaS keys are promoted out of Other so Stripe /
    Brevo do not appear twice. Test keys (``sk_test_``) and low-value vendors
    are never promoted.
    """
    key_l = (key or "").strip().lower()
    rhs = (value or "").strip().strip("'\"")
    if key_l.startswith("appsetting_"):
        key_l = key_l[len("appsetting_") :]
    if not key_l or not rhs:
        return None
    if rhs.lower().startswith("sk_test_"):
        return None
    if any(marker in key_l for marker in _IGNORED_ENV_PROVIDERS):
        return None

    for marker, provider, kind in _ENV_KEY_PROVIDERS:
        if marker in key_l:
            if provider == "aws":
                return None  # handled by AWS pairing
            if provider == "stripe":
                if rhs.startswith("sk_live_"):
                    return "stripe", "stripe_live", rhs
                # Non-live Stripe env values are not promoted.
                return None
            return provider, kind or provider, rhs

    for provider, kind, pattern in _VALUE_KIND_RULES:
        if pattern.fullmatch(rhs):
            return provider, kind, rhs
    return None


def provider_metadata(provider: str, count: int = 0) -> dict[str, Any]:
    key = provider if provider in PROVIDERS else "other"
    return {"id": key, **PROVIDERS[key], "count": count}
