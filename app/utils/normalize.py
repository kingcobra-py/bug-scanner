"""URL and path normalization helpers."""

from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse


_SCHEME_RE = re.compile(r"^https?://", re.I)


def ensure_scheme(url: str, default: str = "https") -> str:
    url = (url or "").strip()
    if not url:
        return ""
    if not _SCHEME_RE.match(url):
        return f"{default}://{url}"
    return url


def normalize_target(url: str) -> str:
    """Normalize a target URL to scheme://host[:port] without trailing slash."""
    url = ensure_scheme(url)
    if not url:
        return ""
    parsed = urlparse(url)
    if not parsed.netloc:
        return ""
    scheme = (parsed.scheme or "https").lower()
    netloc = parsed.netloc.lower()
    # Drop default ports
    if netloc.endswith(":443") and scheme == "https":
        netloc = netloc[:-4]
    if netloc.endswith(":80") and scheme == "http":
        netloc = netloc[:-3]
    return f"{scheme}://{netloc}"


def join_url(base: str, path: str) -> str:
    base = normalize_target(base).rstrip("/")
    path = normalize_path(path)
    return f"{base}{path}"


def normalize_path(path: str) -> str:
    """Normalize a wordlist path: leading slash, strip comments/blanks."""
    if path is None:
        return ""
    path = path.strip()
    if not path or path.startswith("#"):
        return ""
    # Allow absolute URLs to pass through for custom lists
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if not path.startswith("/"):
        path = "/" + path
    # Collapse duplicate slashes except protocol-like //path variants we keep once
    while "//" in path and not path.startswith("//"):
        path = path.replace("//", "/")
    return path


def host_key(url: str) -> str:
    parsed = urlparse(ensure_scheme(url))
    return parsed.netloc.lower()


def origin_variants(url: str) -> list[str]:
    """Return http and https variants of a host."""
    base = normalize_target(url)
    if not base:
        return []
    parsed = urlparse(base)
    host = parsed.netloc
    return [f"https://{host}", f"http://{host}"]


def strip_url_to_host(url: str) -> str:
    parsed = urlparse(ensure_scheme(url))
    return parsed.netloc.lower()


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)[:180]