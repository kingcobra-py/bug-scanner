"""Regression coverage for an OOM found live: a single multi-process worker
grew to ~18GB RSS and got killed by the kernel. Root cause was two
unbounded per-host caches held for the lifetime of the worker process:
httpx's default cookie jar (unlimited, accumulates every Set-Cookie from
every unique host) and HttpClient's soft-404 signature cache."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from app.core.http_client import HostRateLimiter, HttpClient


class CookieSettingHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        self.send_response(200)
        # A distinct cookie per request simulates the real-world case where
        # every unique host (session id, WAF/CDN cookie, load-balancer
        # affinity cookie, ...) sets something different.
        self.send_header("Set-Cookie", f"sid={self.path}; Path=/")
        self.end_headers()
        self.wfile.write(b"ok")


def run_server() -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), CookieSettingHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def test_cookie_jar_never_accumulates_across_requests():
    httpd = run_server()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    client = HttpClient(timeout=2.0, retries=0)

    for i in range(50):
        resp = client.get(f"{base}/path-{i}")
        assert resp.status_code == 200

    # Every response set a cookie, but this scanner never needs
    # cross-request session continuity across the huge number of unrelated
    # hosts it visits, so the jar must be empty after every single request.
    assert len(client._shared_client.cookies.jar) == 0
    client.close()
    httpd.shutdown()


def test_soft404_cache_is_bounded_with_lru_eviction():
    client = HttpClient(timeout=2.0)
    client._soft404_max_entries = 5

    for i in range(20):
        with client._soft404_lock:
            host = f"host-{i}.example"
            client._soft404[host] = {"status": 200, "length": 1, "hash": "x", "title": ""}
            client._soft404.move_to_end(host)
            while len(client._soft404) > client._soft404_max_entries:
                client._soft404.popitem(last=False)

    # Never grows past the cap regardless of how many distinct hosts were
    # probed, and it's the most-recently-seen hosts that survive.
    assert len(client._soft404) == 5
    assert set(client._soft404.keys()) == {f"host-{i}.example" for i in range(15, 20)}
    client.close()


def test_soft404_get_refreshes_lru_order():
    client = HttpClient(timeout=2.0)
    client._soft404_max_entries = 3
    for i in range(3):
        with client._soft404_lock:
            client._soft404[f"host-{i}.example"] = {"status": 200, "length": 1, "hash": "x", "title": ""}

    # Touching host-0 should keep it alive even though it was inserted first.
    assert client.get_soft404_profile("http://host-0.example/") is not None
    with client._soft404_lock:
        client._soft404["host-3.example"] = {"status": 200, "length": 1, "hash": "x", "title": ""}
        client._soft404.move_to_end("host-3.example")
        while len(client._soft404) > client._soft404_max_entries:
            client._soft404.popitem(last=False)

    assert "host-0.example" in client._soft404
    assert "host-1.example" not in client._soft404  # oldest untouched entry evicted instead
    client.close()


def test_rate_limiter_buckets_stay_bounded_across_many_distinct_hosts():
    limiter = HostRateLimiter(per_host=1000.0)
    limiter._MAX_ENTRIES_PER_SHARD = 10

    for i in range(5000):
        limiter.wait(f"unique-host-{i}.example")

    total_entries = sum(len(bucket) for bucket in limiter._next)
    # Bounded per shard regardless of how many thousands of distinct hosts
    # were rate-limited over the life of the worker process.
    assert total_entries <= limiter._MAX_ENTRIES_PER_SHARD * limiter._SHARDS


class HugeBodyHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        # 32 MiB body — large enough that the old ``resp.content[:cap]``
        # pattern would buffer the whole thing before slicing, and small
        # enough for a unit test to finish quickly.
        payload = b"A" * (32 * 1024 * 1024)
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def test_huge_response_body_is_hard_capped():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), HugeBodyHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    client = HttpClient(timeout=10.0, retries=0, max_body_bytes=4096)

    resp = client.get(base + "/blob")
    assert resp.status_code == 200
    assert len(resp.content) == 4096
    assert resp.content == b"A" * 4096

    client.close()
    httpd.shutdown()
