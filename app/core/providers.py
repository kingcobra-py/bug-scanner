"""API/secret provider metadata used by result filters."""

from __future__ import annotations

from typing import Any


PROVIDERS: dict[str, dict[str, str]] = {
    "aws": {"label": "AWS", "color": "#ff9900", "logo": "/static/img/providers/aws.svg"},
    "github": {"label": "GitHub", "color": "#f0f6fc", "logo": "https://cdn.simpleicons.org/github/f0f6fc"},
    "gitlab": {"label": "GitLab", "color": "#fc6d26", "logo": "https://cdn.simpleicons.org/gitlab/fc6d26"},
    "stripe": {"label": "Stripe", "color": "#635bff", "logo": "/static/img/providers/stripe.svg"},
    "sendgrid": {"label": "SendGrid", "color": "#1a82e2", "logo": "/static/img/providers/sendgrid.png"},
    "brevo": {"label": "Brevo", "color": "#0b996e", "logo": "https://cdn.simpleicons.org/brevo/0b996e"},
    "mailgun": {"label": "Mailgun", "color": "#f06b66", "logo": "https://cdn.simpleicons.org/mailgun/f06b66"},
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


def provider_metadata(provider: str, count: int = 0) -> dict[str, Any]:
    key = provider if provider in PROVIDERS else "other"
    return {"id": key, **PROVIDERS[key], "count": count}
