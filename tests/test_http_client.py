from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from app.core.http_client import HttpClient

_REQUEST_COUNTS = {"count": 0}
_COUNT_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path.startswith("/ok"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"hello-ok")
        elif self.path.startswith("/forbid"):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Forbidden")
        elif self.path.startswith("/missing"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"nope")
        elif self.path.startswith("/slow"):
            import time
            time.sleep(2.5)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"slow")
        elif self.path.startswith("/bbscanner-soft404-"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"soft-404-page-title-unique")
        elif self.path.startswith("/softy"):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"soft-404-page-title-unique")
        elif self.path.startswith("/count"):
            with _COUNT_LOCK:
                _REQUEST_COUNTS["count"] += 1
            import time
            time.sleep(2.5)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"slow-counted")
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"root")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS, PUT")
        self.end_headers()

    def do_PUT(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"put-ok")

    def do_POST(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"post-ok")

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()


def run_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def test_timeout_and_ok():
    httpd = run_server()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    client = HttpClient(timeout=1.0, connect_timeout=1.0, retries=0)
    ok = client.get(f"{base}/ok")
    assert ok.status_code == 200
    assert "hello-ok" in ok.text
    slow = client.get(f"{base}/slow")
    assert slow.status_code == 0
    assert "timeout" in slow.error
    client.close()
    httpd.shutdown()


def test_soft404_detection():
    httpd = run_server()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    client = HttpClient(timeout=2.0, retries=0)
    profile = client.build_soft404_profile(base)
    assert profile["length"] > 0
    soft = client.get(f"{base}/softy")
    assert soft.soft404 is True
    real = client.get(f"{base}/ok")
    assert real.soft404 is False
    client.close()
    httpd.shutdown()


def test_methods_rotation():
    httpd = run_server()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    client = HttpClient(timeout=2.0, retries=0)
    results = client.test_methods(f"{base}/ok", ["GET", "POST", "PUT", "OPTIONS", "DELETE"], include_override=False)
    by = {r.method: r.status_code for r in results}
    assert by["GET"] == 200
    assert by["PUT"] == 200
    assert by["OPTIONS"] == 204
    client.close()
    httpd.shutdown()


def test_403_marked():
    httpd = run_server()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    client = HttpClient(timeout=2.0, retries=0)
    resp = client.get(f"{base}/forbid")
    assert resp.status_code == 403
    assert resp.forbidden_but_exists is True
    client.close()
    httpd.shutdown()


def test_post_method():
    httpd = run_server()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    client = HttpClient(timeout=2.0, retries=0)
    resp = client.post(f"{base}/ok", data=b"probe-body", headers={"Content-Type": "application/octet-stream"})
    assert resp.status_code == 200
    assert resp.text == "post-ok"
    client.close()
    httpd.shutdown()


def test_shared_client_counts_real_requests_across_threads():
    httpd = run_server()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    count = 0
    lock = threading.Lock()

    def recorded():
        nonlocal count
        with lock:
            count += 1

    client = HttpClient(timeout=2.0, retries=0, on_request=recorded)
    with ThreadPoolExecutor(max_workers=12) as pool:
        responses = list(pool.map(lambda _: client.get(f"{base}/ok"), range(40)))
    assert all(response.status_code == 200 for response in responses)
    assert count == 40
    # Every worker uses one thread-safe connection pool, not one client each.
    assert client._shared_client is not None
    client.close()
    httpd.shutdown()


def test_probe_live_does_not_retry_on_timeout():
    httpd = run_server()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    with _COUNT_LOCK:
        _REQUEST_COUNTS["count"] = 0
    # retries=3 at the client level would normally mean up to 4 attempts;
    # probe_live must ignore that and try exactly once so dead/filtered
    # hosts don't multiply the time wasted across millions of targets.
    client = HttpClient(timeout=0.3, connect_timeout=0.3, retries=3, retry_backoff=0.05)
    resp = client.probe_live(f"{base}/count")
    assert resp.status_code == 0
    assert "timeout" in resp.error
    with _COUNT_LOCK:
        assert _REQUEST_COUNTS["count"] == 1
    client.close()
    httpd.shutdown()


def test_soft404_profile_uses_no_retry_override():
    httpd = run_server()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    client = HttpClient(timeout=2.0, retries=5)
    captured = {}
    original_get = client.get

    def spy(url, **kwargs):
        captured.update(kwargs)
        return original_get(url, **kwargs)

    client.get = spy
    client.build_soft404_profile(base)
    assert captured.get("retries") == 0
    client.close()
    httpd.shutdown()


def test_module_requests_still_retry_by_default():
    httpd = run_server()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    with _COUNT_LOCK:
        _REQUEST_COUNTS["count"] = 0
    client = HttpClient(timeout=0.3, connect_timeout=0.3, retries=2, retry_backoff=0.05)
    resp = client.get(f"{base}/count")
    assert resp.status_code == 0
    with _COUNT_LOCK:
        # A normal module .get() call (no override) still honors config.retries.
        assert _REQUEST_COUNTS["count"] == 3
    client.close()
    httpd.shutdown()


def test_connection_pool_scales_with_thread_count():
    small = HttpClient(max_connections=100)
    big = HttpClient(max_connections=4000)
    # httpx doesn't expose the configured Limits back on the client publicly,
    # so we read the underlying httpcore pool to confirm the value was wired
    # through (rather than silently falling back to a fixed default).
    small_pool = small._shared_client._transport._pool
    big_pool = big._shared_client._transport._pool
    assert small_pool._max_connections == 100
    assert big_pool._max_connections == 4000
    small.close()
    big.close()