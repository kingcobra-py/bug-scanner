"""Secret / token extraction with parsers + regex packs."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

from app.extractors import patterns as P
from app.extractors.validators import (
    GENERIC_ENV_KV_NAMES,
    confidence_for,
    is_placeholder,
    is_useless_env_assignment,
    looks_like_js_expression,
    looks_like_secret,
    redact,
)
from app.utils.dedupe import value_hash


_NOISE_ENV_PREFIXES = (
    "__NEXT_PRIVATE_",
    "AWS_LAMBDA_",
    "AWS_CONTAINER_",
    "NPM_",
    "KUBERNETES_",
    "WEBSITE_",
    "ECS_",
)
_NOISE_ENV_EXACT = {
    "AWS_EXECUTION_ENV",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "AWS_APP_ENV",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_STS_REGIONAL_ENDPOINTS",
    "HOSTNAME",
    "NODE_VERSION",
    "YARN_VERSION",
    "PORT",
    "HOME",
    "PATH",
    "PWD",
    "SHLVL",
    "NEXT_DEPLOYMENT_ID",
}
_SMTP_ENV_RE = re.compile(r"^(?:APPSETTING_)?(?:SMTP|MAIL|EMAIL)_", re.I)


def _parse_env(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in P.ENV_LINE.finditer(text or ""):
        k, v = m.group(1), m.group(2).strip().replace("\r", "").strip().strip("'\"")
        if k and v and not is_placeholder(v):
            out[k] = v
    return out


def _is_noise_env_key(key: str) -> bool:
    key_u = (key or "").strip()
    if not key_u:
        return True
    if key_u in _NOISE_ENV_EXACT:
        return True
    if any(key_u.startswith(prefix) for prefix in _NOISE_ENV_PREFIXES):
        return True
    if key_u.startswith("NEXT_PUBLIC_") and "SECRET" not in key_u and "PRIVATE" not in key_u:
        return True
    return False


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


_KV_MARKERS = (
    "aws", "github", "gitlab", "stripe", "sendgrid", "brevo",
    "mailgun", "postmark", "slack", "openai", "anthropic", "twilio", "azure",
    "tencent", "aliyun", "smtp", "mail_", "mail-",
    "password", "passwd", "secret", "private", "credential", "access_key",
    "secret_key",
)


_IGNORED_ENV_KEY_MARKERS = (
    "nextauth", "emailjs", "sanity", "paystack", "msi_secret",
)


def _interesting_kv(key: str, value: str) -> bool:
    key_l = key.strip().lower()
    if key_l.startswith("appsetting_"):
        key_l = key_l[len("appsetting_") :]
    value = (value or "").strip().replace("\r", "").strip().strip("'\"")
    if key_l in _NON_SECRET_KEYS:
        return False
    if _is_noise_env_key(key):
        return False
    if any(marker in key_l for marker in _IGNORED_ENV_KEY_MARKERS):
        return False
    if value.lower().startswith("sk_test_"):
        return False
    # SMTP/mail blocks are handled by extract_smtp — avoid duplicate env rows.
    if _SMTP_ENV_RE.match(key):
        return False
    if key_l in GENERIC_ENV_KV_NAMES or key_l.startswith("keyword"):
        return False
    if _looks_like_sentence_or_code(value) or looks_like_js_expression(value):
        return False
    if is_placeholder(value):
        return False
    # Require a provider/credential-shaped key name AND a value that actually
    # looks like a secret. The old ``len >= 8`` escape hatch is what let
    # ``wp_local_password`` and other low-entropy placeholders through.
    if not any(m in key_l for m in _KV_MARKERS):
        return False
    return looks_like_secret(value, min_len=8)


def extract_secrets(text: str, source_url: str = "", redact_values: bool = True) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    text = text or ""

    def add(kind: str, value: str, evidence: str = "", conf: float | None = None) -> None:
        value = (value or "").strip().strip("'\"")
        if not value or is_placeholder(value):
            return
        kind_l = (kind or "").lower()
        if kind_l in P.IGNORED_SECRET_KINDS or kind_l.startswith("generic"):
            return
        # Drop public Google API keys / JWTs even when they arrive via env/JSON KV.
        if value.startswith("AIza") or (value.startswith("eyJ") and value.count(".") >= 2):
            return
        # env rows are stored as KEY=VALUE — validate the RHS / generic LHS too.
        if kind_l == "env" and is_useless_env_assignment(value):
            return
        rhs = value.split("=", 1)[1] if kind_l == "env" and "=" in value else value
        if looks_like_js_expression(rhs) or is_placeholder(rhs):
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
    aws_access = env.get("AWS_ACCESS_KEY_ID") or env.get("AWS_ACCESS_KEY") or ""
    aws_secret = env.get("AWS_SECRET_ACCESS_KEY") or env.get("AWS_SECRET_KEY") or ""
    paired_access: set[str] = set()
    if re.fullmatch(r"(?:AKIA|ASIA|ABIA|ANPA)[0-9A-Z]{16}", aws_access) and aws_secret:
        add("aws_cred", f"{aws_access}:{aws_secret}", evidence="AWS_ACCESS_KEY_ID+AWS_SECRET_ACCESS_KEY", conf=0.95)
        paired_access.add(aws_access)

    for k, v in env.items():
        key_u = k.upper()
        if key_u in {"AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY", "AWS_SECRET_KEY", "AWS_SESSION_TOKEN"}:
            continue
        if _interesting_kv(k, v):
            add("env", f"{k}={v}", evidence=f"{k}=***")

    data = _parse_jsonish(text)
    if data:
        for k, v in data.items():
            if isinstance(v, (str, int, float)) and _interesting_kv(str(k), str(v)):
                add("env", f"{k}={v}", evidence=f"{k}=***")

    # Regex packs — sk_test_ is never emitted.
    seen_token_values: set[str] = set()
    for _, pack in P.PATTERN_PACKS.items():
        for kind, regex in pack:
            for m in regex.finditer(text):
                val = P.first_group(m)
                if not val:
                    continue
                if val.lower().startswith("sk_test_") or kind == "stripe_test":
                    continue
                if val in seen_token_values:
                    continue
                seen_token_values.add(val)
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
        if ak in paired_access:
            continue
        window = text[max(0, am.start() - 500) : am.end() + 500]
        secrets = P.AWS_SECRET_KEY.findall(window) + P.AWS_SECRET_ASSIGN.findall(window)
        paired = False
        for sk in secrets:
            if re.search(r"[A-Za-z]", sk) and re.search(r"[0-9/+=]", sk):
                add("aws_cred", f"{ak}:{sk}", evidence=P.context_window(text, am.start(), am.end()), conf=0.92)
                paired_access.add(ak)
                paired = True
                break
        if not paired:
            add("aws_access_key", ak, evidence=P.context_window(text, am.start(), am.end()), conf=0.88)

    return findings