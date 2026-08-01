"""Technology fingerprinting for WordPress, Joomla, React/Next, generic."""

from __future__ import annotations

import re
from typing import Any

from app.core.http_client import HttpClient, HttpResponse


WP_MARKERS = [
    re.compile(r"wp-content", re.I),
    re.compile(r"wp-includes", re.I),
    re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+WordPress\s*([0-9.]+)?", re.I),
    re.compile(r"/wp-json/", re.I),
]
JOOMLA_MARKERS = [
    re.compile(r"/media/system/js/", re.I),
    re.compile(r"<meta[^>]+name=[\"']generator[\"'][^>]+Joomla", re.I),
    re.compile(r"/components/com_", re.I),
    re.compile(r"option=com_", re.I),
]
NEXT_MARKERS = [
    re.compile(r"/_next/static/", re.I),
    re.compile(r"__NEXT_DATA__", re.I),
    re.compile(r"x-powered-by:\s*Next\.js", re.I),
]
REACT_MARKERS = [
    re.compile(r"\breact(?:[-.]dom)?\b", re.I),
    re.compile(r"data-reactroot", re.I),
    re.compile(r"id=[\"']root[\"']", re.I),
]


def _header_blob(resp: HttpResponse) -> str:
    return "\n".join(f"{k}: {v}" for k, v in (resp.headers or {}).items())


def fingerprint_response(resp: HttpResponse) -> dict[str, Any]:
    body = resp.text or ""
    headers = _header_blob(resp)
    blob = body + "\n" + headers
    tech: list[str] = []
    meta: dict[str, Any] = {}

    if any(p.search(blob) for p in WP_MARKERS):
        tech.append("wordpress")
        m = re.search(r"WordPress\s*([0-9.]+)", blob, re.I)
        if m:
            meta["wordpress_version"] = m.group(1)

    if any(p.search(blob) for p in JOOMLA_MARKERS):
        tech.append("joomla")
        m = re.search(r"Joomla!?\s*([0-9.]+)", blob, re.I)
        if m:
            meta["joomla_version"] = m.group(1)

    if any(p.search(blob) for p in NEXT_MARKERS) or "next.js" in (resp.headers.get("x-powered-by", "").lower()):
        tech.append("nextjs")
        tech.append("react")

    if "react" not in tech and any(p.search(blob) for p in REACT_MARKERS):
        tech.append("react")

    server = resp.headers.get("server", "")
    if server:
        meta["server"] = server
        tech.append(server.split("/")[0].lower())

    powered = resp.headers.get("x-powered-by", "")
    if powered:
        meta["powered_by"] = powered

    # dedupe preserve order
    seen = set()
    tech_u = []
    for t in tech:
        if t not in seen:
            seen.add(t)
            tech_u.append(t)

    return {"tech": tech_u, "meta": meta, "title": HttpClient._extract_title(body)}


def fingerprint_target(http: HttpClient, base_url: str) -> dict[str, Any]:
    resp = http.get(base_url)
    result = fingerprint_response(resp)
    # light secondary probes
    probes = {
        "wordpress": "/wp-login.php",
        "joomla": "/administrator/",
        "nextjs": "/_next/static/",
    }
    for name, path in probes.items():
        if name in result["tech"]:
            continue
        try:
            pr = http.get(base_url.rstrip("/") + path, retry_on_403=False)
            if pr.status_code in (200, 301, 302, 401, 403) and not pr.soft404:
                if name == "wordpress" and ("wordpress" in pr.text.lower() or "wp-" in pr.text.lower() or pr.status_code in (200, 302)):
                    if "wp-login" in path and pr.status_code in (200, 302, 403):
                        result["tech"].append("wordpress")
                if name == "joomla" and (pr.status_code in (200, 302, 403) or "joomla" in pr.text.lower()):
                    result["tech"].append("joomla")
                if name == "nextjs" and (pr.status_code == 200 or "_next" in pr.url):
                    result["tech"].extend(["nextjs", "react"])
        except Exception:
            continue
    # unique
    seen = set()
    result["tech"] = [t for t in result["tech"] if not (t in seen or seen.add(t))]  # type: ignore
    result["live"] = resp.status_code > 0 and not resp.error
    result["status_code"] = resp.status_code
    result["final_url"] = resp.url or base_url
    result["headers"] = resp.headers
    return result