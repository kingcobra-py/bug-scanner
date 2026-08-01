from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from app.core.http_client import HttpClient


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