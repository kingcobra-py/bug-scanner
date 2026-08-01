"""
High-quality regex packs for APIs, secrets, and SMTP.
Adapted from user-provided pattern packs + sample JS scanner patterns.
"""

from __future__ import annotations

import re
from typing import Match, Optional

# --- Cloud / SaaS keys ---
AWS_ACCESS_KEY = re.compile(r"\b((?:AKIA|ASIA|ABIA|ANPA)[0-9A-Z]{16})\b")
AWS_SECRET_KEY = re.compile(r"(?<=['\"])([A-Za-z0-9/+]{40})(?=['\"])")
AWS_SES_HOST = re.compile(r"email-smtp\.[a-z0-9\-]+\.amazonaws\.com", re.I)

AZURE_STORAGE = re.compile(
    r"DefaultEndpointsProtocol=[^;]+;AccountName=([^;]+);AccountKey=([^;]+)",
    re.I,
)

GITHUB_TOKEN = re.compile(
    r"\b(ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|ghu_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|ghr_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22}_[A-Za-z0-9_]{59})\b"
)
GITLAB_TOKEN = re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b")

SENDGRID_KEY = re.compile(r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b")
BREVO_KEY = re.compile(r"\bxkeysib-[A-Za-z0-9]{64}-[A-Za-z0-9]{16}\b", re.I)
XSMTP_KEY = re.compile(r"\bxsmtpsib-[a-fA-F0-9]{64}-[A-Za-z0-9]{16}\b", re.I)
MAILGUN_KEY = re.compile(r"\bkey-[0-9a-zA-Z]{32}\b")
POSTMARK_TOKEN = re.compile(
    r"(?:^|[\s\"'])POSTMARK_(?:SERVER|API)_TOKEN\s*[:=]\s*\"?(?P<token>[0-9A-Za-z]{8}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{4}-[0-9A-Za-z]{12})\"?",
    re.I | re.M,
)

STRIPE_LIVE = re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b")
STRIPE_TEST = re.compile(r"\bsk_test_[0-9a-zA-Z]{24,}\b")
TWILIO_SID = re.compile(r"\b(AC[0-9a-fA-F]{32})\b")
TWILIO_AUTH = re.compile(r"(?i)(?:TWILIO_AUTH_TOKEN|auth_token)\s*[:=]\s*['\"]?([0-9a-fA-F]{32})['\"]?")
TWILIO_B64 = re.compile(r"\bQU[MN][A-Za-z0-9+/]{80,}={0,2}\b")

SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")
JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+?\b")

OPENAI_KEY = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
ANTHROPIC_KEY = re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}\b")
GOOGLE_API_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
FIREBASE_KEY = GOOGLE_API_KEY

TENCENT_AK = re.compile(r"\bAKID[A-Za-z0-9]{13,32}\b")
ALIYUN_AK = re.compile(r"\bLTAI[A-Za-z0-9]{12,21}\b")

GENERIC_API_KEY = re.compile(
    r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.=]{16,})['\"]"
)
BEARER = re.compile(r"(?i)authorization\s*[:=]\s*['\"]?bearer\s+([A-Za-z0-9\-_\.=]+)")

# --- Endpoints ---
ABS_URL = re.compile(r"https?://[^\s\"'<>\\]{4,}", re.I)
API_PATH = re.compile(r"(?i)['\"](/api/v?\d*/[A-Za-z0-9_\-./{}]+)['\"]")
GRAPHQL = re.compile(r"(?i)['\"](/graphql(?:/[A-Za-z0-9_\-./]*)?)['\"]")
FETCH_URL = re.compile(
    r"(?i)(?:fetch|axios\.(?:get|post|put|patch|delete)|XMLHttpRequest|\.open)\s*\(\s*['\"]([^'\"]+)['\"]"
)
BASE_URL_ASSIGN = re.compile(
    r"(?i)(?:baseURL|BASE_URL|API_URL|VITE_[A-Z0-9_]+|REACT_APP_[A-Z0-9_]+|NEXT_PUBLIC_[A-Z0-9_]+)\s*[:=]\s*['\"]([^'\"]+)['\"]"
)

# --- SMTP / mail ---
SMTP_URI = re.compile(
    r"(?i)smtps?://(?:([^:@/\s]+):([^@/\s]+)@)?([A-Za-z0-9.\-]+)(?::(\d+))?"
)
MAIL_HOST = re.compile(
    r"(?im)(?:^|[\s\"'])(?:MAIL|SMTP)_(?:HOST|HOSTNAME|SERVER)\s*[:=]\s*[\"']?(?P<host>[^\s\"'#]+)"
)
MAIL_PORT = re.compile(
    r"(?im)(?:^|[\s\"'])(?:MAIL|SMTP)_(?:PORT|PORT_NUMBER)\s*[:=]\s*[\"']?(?P<port>\d{2,5})"
)
MAIL_USER = re.compile(
    r"(?im)(?:^|[\s\"'])(?:MAIL|SMTP)_(?:USER|USERNAME|USER_NAME)\s*[:=]\s*[\"']?(?P<user>[^\s\"'#]+)"
)
MAIL_PASS = re.compile(
    r"(?im)(?:^|[\s\"'])(?:MAIL|SMTP)_(?:PASS|PASSWORD|PASSWD)\s*[:=]\s*[\"']?(?P<pass>[^\s\"'#]+)"
)
SPRING_MAIL = re.compile(
    r"(?im)spring\.mail\.(host|port|username|password)\s*[:=]\s*[\"']?([^\s\"'#]+)"
)
MAIL_SMTP_PROP = re.compile(
    r"(?im)mail\.smtp\.(host|port|user|password)\s*[:=]\s*[\"']?([^\s\"'#]+)"
)
PROVIDER_HOST = re.compile(
    r"(?i)\b(?:smtp\.(?:sendgrid\.net|mailgun\.org|postmarkapp\.com|gmail\.com)|email-smtp\.[a-z0-9\-]+\.amazonaws\.com|smtp\.mailchimp\.com)\b"
)

# --- Env / config assignment ---
ENV_LINE = re.compile(
    r"(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:[\"']?)([^\"'\n#]+?)(?:[\"'])?\s*$"
)
JS_ASSIGN = re.compile(
    r"(?i)(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*[:=]\s*['\"]([^'\"]{6,})['\"]"
)

# --- Git exposure ---
GIT_HEAD = re.compile(r"^ref:\s+refs/", re.M)
GIT_CONFIG = re.compile(r"(?m)^\[core\]|^\[remote \"origin\"\]")

# JS link extraction
EXTENSIONS = r"(?:js|map|json|env|yml|yaml|xml|txt|config|php|bak)"
JS_LINK = re.compile(
    rf"""<script[^>]+src=["']([^"']+\.(?:js|map))["']|
         <link[^>]+href=["']([^"']+\.(?:js|map|json|css))["']""",
    re.I | re.VERBOSE,
)

PATTERN_PACKS: dict[str, list[tuple[str, re.Pattern]]] = {
    "aws_access_key": [("aws_access_key", AWS_ACCESS_KEY)],
    "github_token": [("github_token", GITHUB_TOKEN)],
    "gitlab_token": [("gitlab_token", GITLAB_TOKEN)],
    "sendgrid": [("sendgrid", SENDGRID_KEY)],
    "brevo": [("brevo", BREVO_KEY)],
    "xsmtp": [("xsmtp", XSMTP_KEY)],
    "mailgun": [("mailgun", MAILGUN_KEY)],
    "stripe": [("stripe_live", STRIPE_LIVE), ("stripe_test", STRIPE_TEST)],
    "slack": [("slack", SLACK_TOKEN)],
    "jwt": [("jwt", JWT)],
    "openai": [("openai", OPENAI_KEY)],
    "anthropic": [("anthropic", ANTHROPIC_KEY)],
    "google_api": [("google_api", GOOGLE_API_KEY)],
    "tencent": [("tencent", TENCENT_AK)],
    "aliyun": [("aliyun", ALIYUN_AK)],
    "generic_api_key": [("generic_api_key", GENERIC_API_KEY)],
    "bearer": [("bearer", BEARER)],
}


def context_window(text: str, start: int, end: int, radius: int = 80) -> str:
    a = max(0, start - radius)
    b = min(len(text), end + radius)
    return text[a:b]


def first_group(match: Match) -> str:
    if match.lastindex:
        for i in range(1, match.lastindex + 1):
            g = match.group(i)
            if g:
                return g
    return match.group(0)