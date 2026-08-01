"""SMTP / mail credential extraction with nearby-key correlation."""

from __future__ import annotations

from typing import Any

from app.extractors import patterns as P
from app.extractors.validators import confidence_for, is_placeholder, redact
from app.utils.dedupe import value_hash


def extract_smtp(text: str, source_url: str = "", redact_values: bool = True) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    text = text or ""

    def add(payload: dict[str, str], evidence: str, conf: float) -> None:
        host = payload.get("host", "")
        user = payload.get("user", "")
        password = payload.get("pass", "")
        if host and is_placeholder(host):
            return
        if password and is_placeholder(password):
            password = ""
        key = value_hash("|".join([host, payload.get("port", ""), user, password, source_url]))
        if key in seen:
            return
        seen.add(key)
        display = dict(payload)
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
            {"host": host, "port": port, "user": user, "pass": password, "scheme": "smtp"},
            evidence=P.context_window(text, m.start(), m.end()),
            conf=0.9 if password else 0.7,
        )

    # KEY=VALUE style blocks
    hosts = list(P.MAIL_HOST.finditer(text))
    for hm in hosts:
        host = hm.group("host")
        window = text[max(0, hm.start() - 400) : hm.end() + 400]
        port_m = P.MAIL_PORT.search(window)
        user_m = P.MAIL_USER.search(window)
        pass_m = P.MAIL_PASS.search(window)
        add(
            {
                "host": host,
                "port": port_m.group("port") if port_m else "",
                "user": user_m.group("user") if user_m else "",
                "pass": pass_m.group("pass") if pass_m else "",
            },
            evidence=P.context_window(text, hm.start(), hm.end()),
            conf=0.88 if pass_m else 0.7,
        )

    # spring / java props
    spring: dict[str, str] = {}
    for m in P.SPRING_MAIL.finditer(text):
        spring[m.group(1).lower()] = m.group(2)
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
        props[m.group(1).lower()] = m.group(2)
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

    # provider host mentions without full creds
    for m in P.PROVIDER_HOST.finditer(text):
        add(
            {"host": m.group(0), "port": "", "user": "", "pass": ""},
            evidence=P.context_window(text, m.start(), m.end()),
            conf=0.55,
        )

    return findings