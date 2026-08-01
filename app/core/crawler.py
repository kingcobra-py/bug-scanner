"""HTML/JS crawler for script sources, robots, sitemap links."""

from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urljoin, urlparse

from app.core.http_client import HttpClient
from app.extractors.patterns import JS_LINK
from app.utils.dedupe import dedupe_strings

HREF_RE = re.compile(r"""(?:href|src)=["']([^"']+)["']""", re.I)
ROBOTS_PATH_RE = re.compile(r"(?im)^(?:allow|disallow)\s*:\s*(/+[^\s#]*)")
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<]+)\s*</loc>", re.I)

BLACKLIST = re.compile(
    r"cloudflare|bootstrap|jquery|favicon|google-analytics|googletagmanager|fonts\.googleapis|unpkg\.com|cdnjs",
    re.I,
)


def extract_links(body: str, base_url: str) -> list[str]:
    links: list[str] = []
    for m in HREF_RE.finditer(body or ""):
        href = m.group(1).strip()
        if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        if BLACKLIST.search(href):
            continue
        links.append(urljoin(base_url, href))
    return dedupe_strings(links)


def extract_script_sources(body: str, base_url: str) -> list[str]:
    out: list[str] = []
    for m in JS_LINK.finditer(body or ""):
        src = m.group(1) or m.group(2) or ""
        if not src or BLACKLIST.search(src):
            continue
        out.append(urljoin(base_url, src))
    # also catch generic .js in href/src
    for link in extract_links(body, base_url):
        path = urlparse(link).path.lower()
        if path.endswith(".js") or path.endswith(".js.map") or "/_next/static/" in path:
            if not BLACKLIST.search(link):
                out.append(link)
    return dedupe_strings(out)


def crawl_target(http: HttpClient, base_url: str, max_extra: int = 50) -> dict[str, list[str]]:
    scripts: list[str] = []
    pages: list[str] = []
    paths: list[str] = []

    home = http.get(base_url)
    if home.status_code and home.text:
        scripts.extend(extract_script_sources(home.text, home.url or base_url))
        pages.extend(extract_links(home.text, home.url or base_url))

    robots = http.get(urljoin(base_url.rstrip("/") + "/", "robots.txt"), retry_on_403=False)
    if robots.status_code == 200 and robots.text and not robots.soft404:
        for m in ROBOTS_PATH_RE.finditer(robots.text):
            paths.append(m.group(1))
        for line in robots.text.splitlines():
            if line.lower().startswith("sitemap:"):
                sm_url = line.split(":", 1)[1].strip()
                if sm_url:
                    sm = http.get(sm_url, retry_on_403=False)
                    if sm.status_code == 200 and sm.text:
                        for loc in SITEMAP_LOC_RE.findall(sm.text)[:max_extra]:
                            pages.append(loc.strip())

    # same-host filter
    host = urlparse(base_url).netloc.lower()
    pages = [p for p in dedupe_strings(pages) if urlparse(p).netloc.lower() in ("", host)][:max_extra]
    scripts = [s for s in dedupe_strings(scripts) if urlparse(s).netloc.lower() in ("", host) or "/_next/" in s]

    # shallow crawl a few pages for more scripts
    for page in pages[:10]:
        resp = http.get(page, retry_on_403=False)
        if resp.status_code == 200 and resp.text and not resp.soft404:
            scripts.extend(extract_script_sources(resp.text, resp.url or page))

    return {
        "scripts": dedupe_strings(scripts)[:200],
        "pages": pages,
        "paths": dedupe_strings(paths),
    }


def filter_same_host(urls: Iterable[str], base_url: str) -> list[str]:
    host = urlparse(base_url).netloc.lower()
    out = []
    for u in urls:
        h = urlparse(u).netloc.lower()
        if h in ("", host):
            out.append(u)
    return dedupe_strings(out)