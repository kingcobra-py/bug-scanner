"""HTTP client with retries, soft-404, 403/404 handling, and method probing."""

from __future__ import annotations

import hashlib
import random
import string
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import quote

import httpx

from app.utils.normalize import join_url, normalize_path


DEFAULT_UA = "BB-Scanner/1.0 (+authorized-security-assessment)"

UA_POOL = [
    DEFAULT_UA,
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
]


@dataclass
class HttpResponse:
    url: str
    status_code: int
    headers: dict[str, str]
    text: str
    content: bytes
    elapsed: float
    error: str = ""
    redirected_from: list[str] = field(default_factory=list)
    soft404: bool = False
    forbidden_but_exists: bool = False
    method: str = "GET"


class HostRateLimiter:
    """Per-host rate limiting without a single global lock.

    Every HTTP attempt (including redirect hops) calls wait() once. A single
    shared lock here means hundreds of worker threads hitting completely
    unrelated hosts still serialize behind each other on every request —
    measured to reduce effective throughput as thread count grows. Sharding
    into a fixed number of lock buckets (by host hash) keeps unrelated hosts
    independent while bounding memory.
    """

    _SHARDS = 64
    _MAX_ENTRIES_PER_SHARD = 5_000

    def __init__(self, per_host: float = 10.0) -> None:
        self.per_host = max(per_host, 0.1)
        self._shard_locks = [threading.Lock() for _ in range(self._SHARDS)]
        # One OrderedDict per shard (not one shared dict) so eviction in a
        # busy shard never has to scan/compete with the timestamps of hosts
        # that hash elsewhere. Scanning hundreds of thousands of distinct
        # hosts previously grew this without any bound for the life of the
        # worker process -- small per-entry, but unbounded is unbounded.
        self._next: list["OrderedDict[str, float]"] = [OrderedDict() for _ in range(self._SHARDS)]

    def _shard_index(self, host: str) -> int:
        return hash(host) % self._SHARDS

    def _shard(self, host: str) -> threading.Lock:
        return self._shard_locks[self._shard_index(host)]

    def wait(self, host: str) -> None:
        min_interval = 1.0 / self.per_host
        idx = self._shard_index(host)
        with self._shard_locks[idx]:
            bucket = self._next[idx]
            now = time.monotonic()
            nxt = bucket.get(host, 0.0)
            delay = max(0.0, nxt - now)
            bucket[host] = max(now, nxt) + min_interval
            bucket.move_to_end(host)
            while len(bucket) > self._MAX_ENTRIES_PER_SHARD:
                bucket.popitem(last=False)
        if delay:
            time.sleep(delay)


class HttpClient:
    def __init__(
        self,
        timeout: float = 8.0,
        connect_timeout: float = 5.0,
        retries: int = 2,
        retry_backoff: float = 0.5,
        verify_tls: bool = False,
        proxy: Optional[str] = None,
        headers: Optional[dict[str, str]] = None,
        max_body_bytes: int = 2_097_152,
        max_redirects: int = 5,
        rate_limit_per_host: float = 50.0,
        user_agent: str = DEFAULT_UA,
        on_request: Optional[Callable[[], None]] = None,
        max_connections: int = 512,
    ) -> None:
        self.timeout = httpx.Timeout(timeout, connect=connect_timeout)
        self.retries = retries
        self.retry_backoff = retry_backoff
        self.verify_tls = verify_tls
        self.proxy = proxy
        self.base_headers = {"User-Agent": user_agent, **(headers or {})}
        self.max_body_bytes = max_body_bytes
        self.max_redirects = max_redirects
        self.limiter = HostRateLimiter(rate_limit_per_host)
        self.on_request = on_request
        # Bounded LRU-ish cache: unbounded growth here was the other half
        # of the same OOM (one entry per unique host, kept for the life of
        # the worker process). A few thousand hosts' worth of profiles is
        # enough locality for the soft-404 check to still help; anything
        # older than that is evicted rather than kept forever.
        self._soft404: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
        self._soft404_max_entries = 20_000
        self._soft404_lock = threading.Lock()
        # Connections must scale with worker threads, or extra threads just
        # queue behind the pool's semaphore instead of doing real work.
        max_connections = max(64, min(int(max_connections), 8000))
        kwargs: dict[str, Any] = {
            "timeout": self.timeout,
            "verify": self.verify_tls,
            "follow_redirects": False,
            "headers": self.base_headers,
            # httpx.Client is thread-safe. One shared pool avoids creating one
            # TLS context/pool per worker thread (~29GB observed at 300
            # threads before this).
            "limits": httpx.Limits(max_connections=max_connections, max_keepalive_connections=max(64, max_connections // 8)),
        }
        if self.proxy:
            kwargs["proxy"] = self.proxy
        self._shared_client = httpx.Client(**kwargs)

    def close(self) -> None:
        self._shared_client.close()

    def _read_body_capped(self, resp: httpx.Response) -> bytes:
        """Read at most max_body_bytes, then stop.

        httpx's ``resp.content`` (and non-stream ``.request()``) buffer the
        *entire* response before we can slice it. On a large multi-host scan
        that meant a handful of fat download/ISO/backup endpoints could push
        a single worker past 20GB RSS and into the OOM killer, even with
        max_body_bytes set. Streaming + early close bounds peak body memory
        to the configured cap per in-flight request.
        """
        chunks: list[bytes] = []
        total = 0
        limit = max(0, int(self.max_body_bytes))
        if limit == 0:
            return b""
        for chunk in resp.iter_bytes():
            if total >= limit:
                break
            if not chunk:
                continue
            need = limit - total
            if len(chunk) > need:
                chunks.append(chunk[:need])
                break
            chunks.append(chunk)
            total += len(chunk)
        return b"".join(chunks)

    def _send(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        data: Any = None,
        json_body: Any = None,
        files: Any = None,
        read_body: bool = True,
    ) -> tuple[str, int, dict[str, str], bytes, Optional[str]]:
        """Perform one HTTP exchange with a hard body-size cap.

        Returns ``(final_url, status_code, headers, body, encoding)``.
        """
        try:
            request_kwargs: dict[str, Any] = {
                "method": method,
                "url": url,
                "headers": headers,
            }
            if json_body is not None:
                request_kwargs["json"] = json_body
            elif files is not None:
                request_kwargs["files"] = files
                if data is not None:
                    request_kwargs["data"] = data
            elif isinstance(data, (bytes, bytearray)):
                request_kwargs["content"] = data
            elif data is not None:
                request_kwargs["data"] = data

            with self._shared_client.stream(**request_kwargs) as resp:
                status = resp.status_code
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                resp_url = str(resp.url)
                encoding = resp.encoding
                # Redirect hops only need status/Location; skip body entirely.
                if read_body and not (300 <= status < 400):
                    body = self._read_body_capped(resp)
                else:
                    body = b""
                return resp_url, status, resp_headers, body, encoding
        finally:
            # This is a stateless recon scanner hitting a huge number of
            # unrelated hosts, never authenticated/session-based crawling
            # that needs cookie continuity. httpx's cookie jar has no size
            # cap and accumulates one entry per unique host for the life of
            # this shared client -- across hundreds of thousands of hosts in
            # a large scan that alone reached ~18GB RSS in one worker
            # process and got it OOM-killed. Wiping it after every request
            # costs nothing (we never read it back) and bounds growth to
            # zero regardless of scan size.
            self._shared_client.cookies.clear()
            if self.on_request:
                try:
                    self.on_request()
                except Exception:
                    pass

    @staticmethod
    def _decode_body(body: bytes, encoding: Optional[str]) -> str:
        try:
            return body.decode(encoding or "utf-8", errors="replace")
        except Exception:
            return body.decode("utf-8", errors="replace")

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        data: Any = None,
        json_body: Any = None,
        files: Any = None,
        allow_redirects: bool = True,
        retry_on_403: bool = True,
        retries: Optional[int] = None,
    ) -> HttpResponse:
        host = httpx.URL(url).host or ""
        self.limiter.wait(host)
        hdrs = {**self.base_headers, **(headers or {})}
        last_err = ""
        chain: list[str] = []
        current = url
        method_u = method.upper()
        max_retries = self.retries if retries is None else max(0, retries)

        for attempt in range(max_retries + 1):
            try:
                t0 = time.monotonic()
                # _send always skips bodies on 3xx hops and caps every other
                # body at max_body_bytes, so following redirects never buffers
                # an unbounded download along the way.
                resp_url, status, resp_headers, body, encoding = self._send(
                    method_u,
                    current,
                    headers=hdrs,
                    data=data,
                    json_body=json_body,
                    files=files,
                    read_body=True,
                )
                hops = 0
                while allow_redirects and 300 <= status < 400 and hops < self.max_redirects:
                    loc = resp_headers.get("location")
                    if not loc:
                        break
                    chain.append(resp_url)
                    current = str(httpx.URL(current).join(loc))
                    hops += 1
                    self.limiter.wait(httpx.URL(current).host or "")
                    resp_url, status, resp_headers, body, encoding = self._send(
                        method_u, current, headers=hdrs, read_body=True
                    )
                elapsed = time.monotonic() - t0
                text = self._decode_body(body, encoding)
                result = HttpResponse(
                    url=resp_url,
                    status_code=status,
                    headers=resp_headers,
                    text=text,
                    content=body,
                    elapsed=elapsed,
                    redirected_from=chain,
                    method=method_u,
                )
                if status in (429, 503) and attempt < max_retries:
                    time.sleep(self.retry_backoff * (2**attempt))
                    continue
                if status == 403 and retry_on_403:
                    alt = self._retry_403(method_u, resp_url, hdrs)
                    if alt and alt.status_code != 403:
                        return alt
                    result.forbidden_but_exists = self._looks_like_forbidden(result)
                if status == 404:
                    alt = self._retry_404_variants(method_u, url, hdrs)
                    if alt and alt.status_code not in (0, 404):
                        return alt
                profile = self.get_soft404_profile(resp_url)
                if profile and self.is_soft404(result, profile):
                    result.soft404 = True
                return result
            except httpx.TimeoutException as e:
                last_err = f"timeout:{e.__class__.__name__}"
                if attempt < max_retries:
                    time.sleep(self.retry_backoff * (2**attempt))
                    continue
                return HttpResponse(url=url, status_code=0, headers={}, text="", content=b"", elapsed=0.0, error=last_err, method=method_u)
            except Exception as e:
                last_err = f"error:{e.__class__.__name__}:{e}"
                if attempt < max_retries:
                    time.sleep(self.retry_backoff * (2**attempt))
                    continue
                return HttpResponse(url=url, status_code=0, headers={}, text="", content=b"", elapsed=0.0, error=last_err, method=method_u)
        return HttpResponse(url=url, status_code=0, headers={}, text="", content=b"", elapsed=0.0, error=last_err, method=method_u)

    def get(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> HttpResponse:
        return self.request("POST", url, **kwargs)

    def _retry_403(self, method: str, url: str, headers: dict[str, str]) -> Optional[HttpResponse]:
        variants = [
            {**headers, "User-Agent": random.choice(UA_POOL), "Referer": url.rsplit("/", 1)[0] + "/"},
            {**headers, "User-Agent": random.choice(UA_POOL), "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
            {**headers, "User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)", "Accept": "*/*"},
        ]
        for hdr in variants:
            try:
                self.limiter.wait(httpx.URL(url).host or "")
                resp_url, status, resp_headers, body, encoding = self._send(
                    method, url, headers=hdr, read_body=True
                )
                if status != 403:
                    return HttpResponse(
                        url=resp_url,
                        status_code=status,
                        headers=resp_headers,
                        text=self._decode_body(body, encoding),
                        content=body,
                        elapsed=0.0,
                        method=method,
                    )
            except Exception:
                continue
        # path variants
        for alt_url in self._path_variants(url):
            try:
                self.limiter.wait(httpx.URL(alt_url).host or "")
                resp_url, status, resp_headers, body, encoding = self._send(
                    method, alt_url, headers=headers, read_body=True
                )
                if status not in (403, 404, 0):
                    return HttpResponse(
                        url=resp_url,
                        status_code=status,
                        headers=resp_headers,
                        text=self._decode_body(body, encoding),
                        content=body,
                        elapsed=0.0,
                        method=method,
                    )
            except Exception:
                continue
        return None

    def _retry_404_variants(self, method: str, url: str, headers: dict[str, str]) -> Optional[HttpResponse]:
        for alt_url in self._path_variants(url):
            try:
                self.limiter.wait(httpx.URL(alt_url).host or "")
                resp_url, status, resp_headers, body, encoding = self._send(
                    method, alt_url, headers=headers, read_body=True
                )
                if status not in (404, 0):
                    return HttpResponse(
                        url=resp_url,
                        status_code=status,
                        headers=resp_headers,
                        text=self._decode_body(body, encoding),
                        content=body,
                        elapsed=0.0,
                        method=method,
                    )
            except Exception:
                continue
        return None

    @staticmethod
    def _path_variants(url: str) -> list[str]:
        try:
            u = httpx.URL(url)
        except Exception:
            return []
        path = u.path or "/"
        variants = []
        # trailing slash
        if path.endswith("/"):
            variants.append(str(u.copy_with(path=path.rstrip("/") or "/")))
        else:
            variants.append(str(u.copy_with(path=path + "/")))
        # double slash after host
        if path.startswith("/") and not path.startswith("//"):
            variants.append(str(u.copy_with(path="/" + path)))
        # encoded dot segment for .git style
        if "/." in path:
            variants.append(str(u.copy_with(path=path.replace("/.", "/%2e"))))
        return list(dict.fromkeys(variants))

    @staticmethod
    def _looks_like_forbidden(resp: HttpResponse) -> bool:
        if resp.status_code != 403:
            return False
        body = (resp.text or "").lower()
        markers = ["forbidden", "access denied", "not authorized", "403", "blocked"]
        return any(m in body for m in markers) or len(resp.content) > 0

    def build_soft404_profile(self, base_url: str) -> dict[str, Any]:
        rand = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        probe = join_url(base_url, f"/bbscanner-soft404-{rand}")
        # This is a synthetic self-check against an already-confirmed-live
        # host, not a real target request — retrying it just wastes time.
        resp = self.get(probe, retry_on_403=False, retries=0)
        profile = {
            "status": resp.status_code,
            "length": len(resp.content),
            "hash": hashlib.sha256(resp.content).hexdigest()[:16],
            "title": self._extract_title(resp.text),
        }
        with self._soft404_lock:
            host = httpx.URL(base_url).host or base_url
            self._soft404[host] = profile
            self._soft404.move_to_end(host)
            while len(self._soft404) > self._soft404_max_entries:
                self._soft404.popitem(last=False)
        return profile

    def get_soft404_profile(self, url: str) -> Optional[dict[str, Any]]:
        host = httpx.URL(url).host or ""
        with self._soft404_lock:
            profile = self._soft404.get(host)
            if profile is not None:
                self._soft404.move_to_end(host)
            return profile

    @staticmethod
    def is_soft404(resp: HttpResponse, profile: dict[str, Any]) -> bool:
        if resp.status_code == 0:
            return False
        if resp.status_code != profile.get("status"):
            return False
        body_hash = hashlib.sha256(resp.content).hexdigest()[:16]
        if body_hash == profile.get("hash"):
            return True
        length = len(resp.content)
        plen = int(profile.get("length") or 0)
        if plen and abs(length - plen) <= max(20, int(plen * 0.05)):
            title = HttpClient._extract_title(resp.text)
            if title and title == profile.get("title"):
                return True
        return False

    @staticmethod
    def _extract_title(html: str) -> str:
        if not html:
            return ""
        lower = html.lower()
        start = lower.find("<title")
        if start < 0:
            return ""
        start = lower.find(">", start)
        end = lower.find("</title>", start)
        if start < 0 or end < 0:
            return ""
        return html[start + 1 : end].strip()[:200]

    def probe_live(self, url: str) -> HttpResponse:
        # This is the initial liveness check across the whole target list —
        # at scale most targets are dead/filtered, so retrying a timeout here
        # doubles/triples the time wasted on hosts that will never respond.
        # Real per-path module requests still use the configured retry count.
        return self.get(url, retries=0)

    def test_methods(
        self,
        url: str,
        methods: list[str],
        include_override: bool = True,
    ) -> list[HttpResponse]:
        results: list[HttpResponse] = []
        for method in methods:
            results.append(self.request(method, url, retry_on_403=False, allow_redirects=False))
        if include_override:
            for override in ("PUT", "DELETE", "PATCH"):
                results.append(
                    self.request(
                        "POST",
                        url,
                        headers={"X-HTTP-Method-Override": override},
                        retry_on_403=False,
                        allow_redirects=False,
                    )
                )
        return results