from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
from urllib.parse import unquote, urlparse

from app.core.http_client import HttpClient
from app.core.progress import ProgressManager
from app.modules.joomla import JoomlaModule
from app.modules.react2shell import ReactModule
from app.modules.wordpress import WordPressModule
from app.storage.db import ScanStore
from app.storage.models import ScanConfig, ScanContext, TargetContext

FIX = Path(__file__).parent / "fixtures"


class CMSFixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        query = parsed.query
        key = path
        if query:
            key = f"{path}?{query}"

        mapping = {
            "/": (FIX / "next_home.html").read_bytes(),
            "/package.json": (FIX / "next_package.json").read_bytes(),
            "/_next/static/chunks/main-app.js": b"console.log('next-app');",
            "/_next/static/chunks/app/layout.js": b"export default function Layout(){}",
            "/readme.html": (FIX / "wp_readme.html").read_bytes(),
            "/wp-login.php": b"<html>WordPress login</html>",
            "/wp-json/": b'{"name":"WP Fixture","namespaces":["wp/v2","batch/v1"]}',
            "/wp-json/batch/v1": b'{"code":"rest_no_route","message":"batch endpoint"}',
            "/wp-json/wp/v2/users": b'[{"id":1,"name":"admin","slug":"admin"}]',
            "/wp-content/uploads/": b'<a href="/wp-content/uploads/shell.php">shell.php</a>',
            "/plugins/editors/jce/jce.xml": (FIX / "joomla_jce.xml").read_bytes(),
            "/index.php": b'{"feeds":[{"title":"jce"}]}' if "task=cpanel.feed" in query else b"joomla-index",
            "/images/": b'<a href="/images/imgtest.php">imgtest.php</a>',
            "/administrator/": b"<html>Joomla Administrator com_login</html>",
            "/configuration.php": (
                b"<?php class JConfig { public $secret='a1b2c3d4e5f6g7h8i9j0'; "
                b"public $password='SuperSecretPass1'; "
                b"public $live_site='https://cms.nightwatch.local'; }\n"
                b"// ghp_" + (b"a" * 36) + b"\n"
                b"// SG." + (b"a" * 22) + b"." + (b"b" * 43) + b"\n"
            ),
            "/wp-config.php": (
                b"<?php define('DB_NAME','wp');\n"
                b"define('AWS_KEY','AKIA" + (b"F" * 16) + b"');\n"
                b"define('STRIPE','sk_live_" + (b"c" * 24) + b"');\n"
            ),
            "/api/index.php/v1": b'{"routes":["/api/index.php/v1/content/articles","/api/index.php/v1/users"]}',
            "/api/index.php/v1/content/articles": b'{"data":[{"type":"articles","links":{"self":"/api/index.php/v1/content/articles"}}]}',
            "/api/index.php/v1/users": b'{"data":[{"type":"users"}]}',
        }
        if path.startswith("/bbscanner-soft404-"):
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not-found-template")
            return
        if key in mapping or path in mapping:
            body = mapping.get(key, mapping.get(path))
            self.send_response(200)
            if path == "/":
                self.send_header("x-powered-by", "Next.js")
                self.send_header("rsc", "1")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"missing")


def _start_fixture(tmp_path, modules: list[str]):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), CMSFixtureHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    origin = f"http://127.0.0.1:{httpd.server_address[1]}"
    http = HttpClient(timeout=2.0, retries=0)
    http.build_soft404_profile(origin)
    progress = ProgressManager(enable_cli=False)
    progress.start(50)
    ctx = ScanContext(
        config=ScanConfig(targets=[origin], output_dir=str(tmp_path), modules=modules, probe_both_schemes=False),
        output_dir=tmp_path,
        stop_event=threading.Event(),
        progress=progress,
        store=ScanStore(tmp_path / "db.sqlite"),
        http=http,
    )
    return ctx, http, httpd, origin


def test_react_module_version_and_rsc(tmp_path):
    ctx, http, httpd, origin = _start_fixture(tmp_path, ["react"])
    target = TargetContext(url=origin, live=True, tech=["nextjs", "react"], headers={"rsc": "1"})
    findings = ReactModule().run(target, ctx)
    http.close()
    httpd.shutdown()
    titles = " | ".join(f.title for f in findings)
    assert "React2Shell affected package version: next@15.0.3" in titles
    assert "React Server Components surface headers present" in titles
    assert any("cve-2025-55182" in f.tags for f in findings)


def test_wordpress_module_wp2shell_signals(tmp_path):
    ctx, http, httpd, origin = _start_fixture(tmp_path, ["wordpress"])
    target = TargetContext(url=origin, live=True, tech=["wordpress"], meta={"wordpress_version": "6.9.2"})
    findings = WordPressModule().run(target, ctx)
    http.close()
    httpd.shutdown()
    titles = " | ".join(f.title for f in findings)
    assert "WordPress 6.9.2 matches wp2shell pre-authentication RCE chain" in titles
    assert "WordPress REST batch endpoint reachable" in titles
    assert any("Executable file listed under wp-content/uploads" in f.title for f in findings)
    assert "Priority secrets extracted from wp-config" in titles
    assert any("priority-secrets" in f.tags for f in findings)


def test_joomla_module_jce_and_webshell_indicator(tmp_path):
    ctx, http, httpd, origin = _start_fixture(tmp_path, ["joomla"])
    target = TargetContext(url=origin, live=True, tech=["joomla"])
    findings = JoomlaModule().run(target, ctx)
    http.close()
    httpd.shutdown()
    titles = " | ".join(f.title for f in findings)
    assert "JCE 2.9.80 matches CVE-2026-48907 exposure range" in titles
    assert "JCE cpanel.feed proxy endpoint reachable" in titles
    assert any("Executable file listed under /images" in f.title for f in findings)
    assert "Priority secrets extracted from Joomla response" in titles
    assert any("priority-secrets" in f.tags for f in findings)
    assert any(
        f.extracted.get("extractor") == "priority_secrets"
        for f in findings
        if f.extracted.get("secrets")
    )
