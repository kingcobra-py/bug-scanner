"""SMTP / mail credential extraction with nearby-key correlation."""

from __future__ import annotations

from typing import Any

from app.extractors import patterns as P
from app.extractors.validators import is_placeholder, redact
from app.utils.dedupe import value_hash

_FIELD_ALIASES = {
    "host": {"host", "hostname", "server"},
    "port": {"port", "port_number"},
    "user": {"user", "username", "user_name", "email", "from"},
    "pass": {"pass", "password", "passwd", "pass_word"},
}


def _clean(value: str) -> str:
    return (value or "").replace("\r", "").strip().strip("'\"")


def _collect_mail_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for m in P.MAIL_KV_LINE.finditer(text or ""):
        key = (m.group("key") or "").lower()
        value = _clean(m.group("value") or "")
        if not value:
            continue
        for field, aliases in _FIELD_ALIASES.items():
            if key in aliases:
                fields[field] = value
                break
    # Also accept the dedicated named groups if MAIL_KV_LINE missed a variant.
    for m in P.MAIL_HOST.finditer(text or ""):
        fields.setdefault("host", _clean(m.group("host")))
    for m in P.MAIL_PORT.finditer(text or ""):
        fields.setdefault("port", _clean(m.group("port")))
    for m in P.MAIL_USER.finditer(text or ""):
        fields.setdefault("user", _clean(m.group("user")))
    for m in P.MAIL_PASS.finditer(text or ""):
        fields.setdefault("pass", _clean(m.group("pass")))
    return fields


def extract_smtp(text: str, source_url: str = "", redact_values: bool = True) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    text = text or ""

    def add(payload: dict[str, str], evidence: str, conf: float) -> None:
        host = _clean(payload.get("host", ""))
        user = _clean(payload.get("user", ""))
        password = _clean(payload.get("pass", ""))
        port = _clean(payload.get("port", ""))
        if host and is_placeholder(host):
            return
        # SendGrid/Resend commonly use literal username "apikey" / "resend".
        if user and is_placeholder(user) and user.lower() not in {"apikey", "api_key", "resend"}:
            user = ""
        if password and is_placeholder(password):
            return
        # Skip provider-host noise and incomplete rows.
        if not password:
            return
        if not host and not user:
            return
        key = value_hash("|".join([host, port, user, password, source_url]))
        if key in seen:
            return
        seen.add(key)
        display = {"host": host, "port": port, "user": user, "pass": password}
        for extra_key, extra_val in payload.items():
            if extra_key not in display and extra_val:
                display[extra_key] = _clean(str(extra_val))
        if redact_values:
            if display.get("pass"):
                display["pass"] = redact(display["pass"])
            if display.get("user") and "@" not in display["user"]:
                display["user"] = redact(display["user"])
        findings.append(
            {
                "kind": "smtp",
                "value": display,
                "value_hash": key,
                "evidence": evidence[:240],
                "confidence": conf,
                "source_url": source_url,
            }
        )

    # URI form
    for m in P.SMTP_URI.finditer(text):
        user, password, host, port = m.group(1) or "", m.group(2) or "", m.group(3) or "", m.group(4) or ""
        add(
            {"host": host, "port": port or "", "user": user, "pass": password, "scheme": "smtp"},
            evidence=P.context_window(text, m.start(), m.end()),
            conf=0.9 if password else 0.7,
        )

    # Whole-document KEY=VALUE mail/smtp/email block (handles out-of-order lines).
    fields = _collect_mail_fields(text)
    if fields.get("host") or (fields.get("user") and fields.get("pass")):
        add(
            {
                "host": fields.get("host", ""),
                "port": fields.get("port", ""),
                "user": fields.get("user", ""),
                "pass": fields.get("pass", ""),
            },
            evidence="SMTP/MAIL/EMAIL env block",
            conf=0.9 if fields.get("pass") else 0.72,
        )

    # spring / java props
    spring: dict[str, str] = {}
    for m in P.SPRING_MAIL.finditer(text):
        spring[m.group(1).lower()] = _clean(m.group(2))
    if spring.get("host"):
        add(
            {
                "host": spring.get("host", ""),
                "port": spring.get("port", ""),
                "user": spring.get("username", ""),
                "pass": spring.get("password", ""),
            },
            evidence="spring.mail.*",
            conf=0.85,
        )

    props: dict[str, str] = {}
    for m in P.MAIL_SMTP_PROP.finditer(text):
        props[m.group(1).lower()] = _clean(m.group(2))
    if props.get("host"):
        add(
            {
                "host": props.get("host", ""),
                "port": props.get("port", ""),
                "user": props.get("user", ""),
                "pass": props.get("password", ""),
            },
            evidence="mail.smtp.*",
            conf=0.8,
        )

    # Provider host mentions alone are noise — only keep when nearby password/user exists.
    for m in P.PROVIDER_HOST.finditer(text):
        window = text[max(0, m.start() - 400) : m.end() + 400]
        nearby = _collect_mail_fields(window)
        if nearby.get("pass") or nearby.get("user"):
            add(
                {
                    "host": _clean(m.group(0)),
                    "port": nearby.get("port", ""),
                    "user": nearby.get("user", ""),
                    "pass": nearby.get("pass", ""),
                },
                evidence=P.context_window(text, m.start(), m.end()),
                conf=0.8 if nearby.get("pass") else 0.65,
            )

    jconfig: dict[str, str] = {}
    for m in P.JCONFIG_SMTP_FIELD.finditer(text):
        jconfig[m.group("key").lower()] = _clean(m.group("value"))
    if jconfig.get("smtphost"):
        add(
            {
                "host": jconfig.get("smtphost", ""),
                "port": jconfig.get("smtpport", ""),
                "user": jconfig.get("smtpuser", ""),
                "pass": jconfig.get("smtppass", ""),
                "secure": jconfig.get("smtpsecure", ""),
                "mailer": jconfig.get("mailer", ""),
            },
            evidence="JConfig $smtphost block",
            conf=0.92 if jconfig.get("smtppass") else 0.75,
        )

    wp_smtp: dict[str, str] = {}
    for m in P.WP_DEFINE_SMTP.finditer(text):
        wp_smtp[m.group("key").lower()] = _clean(m.group("value"))
    if wp_smtp.get("host"):
        add(
            {
                "host": wp_smtp.get("host", ""),
                "port": wp_smtp.get("port", ""),
                "user": wp_smtp.get("user", ""),
                "pass": wp_smtp.get("pass", ""),
                "scheme": "smtp",
            },
            evidence="wp-config SMTP define() block",
            conf=0.9 if wp_smtp.get("pass") else 0.72,
        )

    return findings
