"""Placeholder filtering, entropy checks, and redaction helpers."""

from __future__ import annotations

import math
import re
from collections import Counter

PLACEHOLDER_PATTERNS = [
    re.compile(p, re.I)
    for p in [
        r"^your[-_]?password$",
        r"^password$",
        r"^changeme$",
        r"^xxx+$",
        r"^<.*>$",
        r"^\$\{.*\}$",
        r"^%.*%$",
        r"^example\.com$",
        r"^localhost$",
        r"^127\.0\.0\.1$",
        r"^null$",
        r"^none$",
        r"^todo$",
        r"^fix$",
        r"^secret$",
        r"^some[-_]?secret([-_]?key)?$",
        r"^secret[-_]?key$",
        r"^your[-_]?secret([-_]?key)?$",
        r"^my[-_]?secret([-_]?key)?$",
        r"^apikey$",
        r"^api_key$",
        r"^token$",
        r"^test$",
        r"^dummy$",
        r"^sample$",
        r"^xxxx+",
        r"^yyyy+",
        r"^abcd+",
        r"^1234+$",
        r"^0{6,}$",
        r"^replace[_-]?me$",
        r"^replace[_-]?me[_-].+",
        r"^insert[_-]?.*$",
        r"^<.*>$",
        r"^\[.*\]$",
        # Common local/dev WordPress / CMS placeholders
        r"^wp[_-]?local([_-]?password)?$",
        r"^wordpress$",
        r"^admin$",
        r"^root$",
        r"^toor$",
        r"^pass(word)?1234?$",
        r"^local[_-]?pass(word)?$",
        r"^dev[_-]?pass(word)?$",
        r"^default[_-]?pass(word)?$",
        r"^true$",
        r"^false$",
        r"^yes$",
        r"^no$",
        r"^on$",
        r"^off$",
    ]
]

BOOLISH_VALUES = frozenset({
    "true", "false", "yes", "no", "on", "off", "1", "0", "null", "undefined",
})

LOW_VALUE_HOSTS = {
    "example.com",
    "example.org",
    "localhost",
    "127.0.0.1",
    "test.com",
    "domain.com",
}


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_placeholder(value: str) -> bool:
    v = (value or "").strip().strip("'\"")
    if not v:
        return True
    if len(v) < 4:
        return True
    for pat in PLACEHOLDER_PATTERNS:
        if pat.search(v):
            return True
    lowered = v.lower()
    if any(x in lowered for x in ("your-", "your_", "xxx", "changeme", "example.com", "lorem")):
        return True
    # wp_local_password / my_local_secret / test_password style placeholders
    if re.search(r"(^|_)(local|dummy|sample|demo|example|default|placeholder)(_|$)", lowered):
        return True
    return False


# Bare LHS names that are almost never credentials when seen as KEY=VALUE in JS.
GENERIC_ENV_KV_NAMES = frozenset({
    "api_key", "apikey", "api-key", "api_token", "token", "access_token",
    "auth_token", "authorization", "key", "secret", "password", "passwd",
    "bearer", "jwt", "id_token", "keyword", "keywordq", "keyworda",
})


def looks_like_js_expression(value: str) -> bool:
    """True for JS member/expr noise the env-line parser pulls from .js files."""
    v = (value or "").strip().strip("'\"")
    if not v:
        return True
    # Trailing ``?`` is almost always a ternary leftover (``key = method ?``).
    if v.endswith(",") or v.endswith(";") or v.endswith("?"):
        return True
    if re.search(r"[(){}\[\]`$]|=>|\bthis\b|\bfunction\b|\breturn\b", v):
        return True
    if re.fullmatch(r"[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)+", v.rstrip(",;")):
        return True
    return False


def is_boolish_value(value: str) -> bool:
    return (value or "").strip().strip("'\"").lower() in BOOLISH_VALUES


def is_useless_env_assignment(value: str) -> bool:
    """True for stored ``KEY=VALUE`` env rows that are JS/query noise."""
    raw = (value or "").strip()
    if not raw or "=" not in raw:
        return False
    lhs, rhs = raw.split("=", 1)
    lhs_l = lhs.strip().lower()
    rhs_s = rhs.strip().strip("'\"")
    if lhs_l in GENERIC_ENV_KV_NAMES or lhs_l.startswith("keyword"):
        return True
    if is_boolish_value(rhs_s):
        return True
    if looks_like_js_expression(rhs_s) or is_placeholder(rhs_s):
        return True
    return False


def looks_like_secret(value: str, min_entropy: float = 3.0, min_len: int = 12) -> bool:
    v = (value or "").strip().strip("'\"")
    if is_placeholder(v):
        return False
    if len(v) < min_len:
        return False
    # structured keys can be shorter entropy but strong format
    if re.match(r"^(AKIA|ASIA|ghp_|gho_|glpat-|SG\.|sk_live_|sk-ant-|xox)", v):
        return True
    # sk_test_ intentionally excluded — test keys are not reported.
    return shannon_entropy(v) >= min_entropy


def is_interesting_url(url: str) -> bool:
    u = (url or "").strip()
    if not u or is_placeholder(u):
        return False
    low = u.lower()
    for host in LOW_VALUE_HOSTS:
        if host in low:
            return False
    return True


def redact(value: str, show_last: int = 4) -> str:
    v = value or ""
    if len(v) <= show_last:
        return "*" * len(v)
    return ("*" * max(len(v) - show_last, 4)) + v[-show_last:]


def confidence_for(kind: str, value: str, has_context: bool = False) -> float:
    base = {
        "aws_access_key": 0.9,
        "github_token": 0.95,
        "gitlab_token": 0.95,
        "sendgrid": 0.95,
        "brevo": 0.95,
        "stripe_live": 0.95,
        "stripe_test": 0.7,
        "slack": 0.9,
        "jwt": 0.55,
        "smtp": 0.85,
        "api_endpoint": 0.65,
        "generic_api_key": 0.55,
        "env": 0.7,
        "git_exposure": 0.95,
    }.get(kind, 0.5)
    if looks_like_secret(value):
        base = min(1.0, base + 0.05)
    if has_context:
        base = min(1.0, base + 0.05)
    if is_placeholder(value):
        return 0.05
    return round(base, 2)