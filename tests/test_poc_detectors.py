"""Unit tests for PoC-derived safe detectors."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from app.core.http_client import HttpClient
from app.exploits.joomla_rce.detector import JoomlaJceDetector
from app.exploits.react2shell.detector import React2ShellDetector
from app.exploits.wp2shell.detector import Wp2ShellDetector, batch_marker_codes, has_route_confusion_markers

FIX = Path(__file__).parent / "fixtures"


class DetectorFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _write(self, code: int, body: bytes, headers: dict | None = None):
        self.send_response(code)
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/":
            body = (
                b'<html><head><meta name="generator" content="WordPress 6.4.3" />'
                b'"csrf.token":"0123456789abcdef0123456789abcdef"'
                b'</head><body>joomla</body></html>'
            )
            self._write(200, body, {"rsc": "1", "Content-Type": "text/html"})
            return

        if path == "/wp-json/":
            self._write(200, b'{"generator":"https://wordpress.org/?v=6.4.3","routes":{}}')
            return

        if path == "/readme.html":
            self._write(200, b"<!DOCTYPE html><html><body><p>Version 6.4.3</p></body></html>")
            return

        if path == "/package.json":
            self._write(200, FIX.joinpath("next_package.json").read_bytes())
            return

        if path.endswith("jce.xml"):
            self._write(200, FIX.joinpath("joomla_jce.xml").read_bytes())
            return

        if path == "/index.php" and query.get("option") == ["com_jce"]:
            self._write(200, b'{"feeds":[{"title":"jce"}]}')
            return

        self._write(404, b"missing")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" and "rest_route=/batch/v1" in parsed.query:
            payload = {
                "responses": [
                    {"body": {"code": "parse_path_failed"}},
                    {"body": {"code": "block_cannot_read"}},
                    {"body": {"code": "rest_batch_not_allowed"}},
                ]
            }
            self._write(207, json.dumps(payload).encode())
            return

        if parsed.path == "/":
            self._write(500, b'{"digest":"NEXT_REDIRECT probe"}')
            return

        self._write(404, b"missing")


def _start_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), DetectorFixtureHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}"


def test_batch_marker_helpers():
    body = json.dumps(
        {
            "responses": [
                {"body": {"code": "parse_path_failed"}},
                {"body": {"code": "block_cannot_read"}},
                {"body": {"code": "rest_batch_not_allowed"}},
            ]
        }
    )
    codes = batch_marker_codes(body)
    assert has_route_confusion_markers(codes)


def test_wp2shell_detector_marker_probe(tmp_path):
    httpd, origin = _start_server()
    http = HttpClient(timeout=2.0, retries=0)
    result = Wp2ShellDetector(http, origin).scan()
    http.close()
    httpd.shutdown()
    assert result["probe"]["route_confusion"] is True
    assert any(h["affected"] for h in result["version_hints"])


def test_joomla_detector_preconditions(tmp_path):
    httpd, origin = _start_server()
    http = HttpClient(timeout=2.0, retries=0)
    result = JoomlaJceDetector(http, origin).scan()
    http.close()
    httpd.shutdown()
    assert result["jce_present"] is True
    assert result["proxy_reachable"] is True
    assert result["csrf_token_present"] is True
    assert result["preconditions_met"] == 3


def test_react2shell_detector_surface(tmp_path):
    httpd, origin = _start_server()
    http = HttpClient(timeout=2.0, retries=0)
    result = React2ShellDetector(http, origin).scan()
    http.close()
    httpd.shutdown()
    assert "rsc" in result["rsc_headers"]
    assert result["next_action_accepts"] is True
    assert result["rsc_surface_active"] is True
