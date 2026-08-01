from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

from app.core.engine import ScanEngine
from app.extractors.patterns import GIT_HEAD
from app.modules.git_exposure import GitExposureModule
from app.storage.db import ScanStore
from app.storage.models import ScanConfig, ScanContext, TargetContext
from app.core.http_client import HttpClient
from app.core.progress import ProgressManager

FIX = Path(__file__).parent / "fixtures"


def test_git_head_pattern():
    text = (FIX / "git_head.txt").read_text()
    assert GIT_HEAD.search(text)


class FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        mapping = {
            "/": (FIX / "wp_home.html").read_bytes(),
            "/.git/HEAD": (FIX / "git_head.txt").read_bytes(),
            "/.env": (FIX / "sample.env").read_bytes(),
            "/static/js/app.js": (FIX / "sample.js").read_bytes(),
            "/wp-login.php": b"<html>WordPress login</html>",
        }
        # soft404 random
        if self.path.startswith("/bbscanner-soft404-"):
            body = b"not-found-template"
            self.send_response(404)
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path in mapping:
            body = mapping[self.path]
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"missing")


def test_e2e_local_fixture(tmp_path):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    out = tmp_path / "scans"
    store = ScanStore(out / "t.db")
    engine = ScanEngine(store=store, enable_cli_progress=False)
    cfg = ScanConfig(
        targets=[base],
        threads=4,
        timeout=3.0,
        modules=["git", "config", "js", "wordpress"],
        output_dir=str(out),
        formats=["json", "md", "csv"],
        probe_both_schemes=False,
        verbose=True,
    )
    report = engine.run(cfg)
    httpd.shutdown()
    assert "error" not in report or not report.get("error")
    findings = report.get("findings", [])
    types = {f.get("type") for f in findings}
    titles = " ".join(f.get("title", "") for f in findings)
    assert any("git" in (f.get("type") or "") or "git" in (f.get("title") or "").lower() for f in findings)
    assert any(".env" in (f.get("url") or "") or "env" in (f.get("type") or "") for f in findings)
    assert (out / cfg.scan_id / "report.json").exists()


def test_git_module_direct(tmp_path):
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    http = HttpClient(timeout=2.0, retries=0)
    stop = threading.Event()
    progress = ProgressManager(enable_cli=False)
    progress.start(10)
    ctx = ScanContext(
        config=ScanConfig(targets=[base], output_dir=str(tmp_path), modules=["git"], probe_both_schemes=False),
        output_dir=tmp_path,
        stop_event=stop,
        progress=progress,
        store=ScanStore(tmp_path / "db.sqlite"),
        http=http,
    )
    mod = GitExposureModule(extra_paths=["/.git/HEAD"])
    target = TargetContext(url=base, live=True)
    findings = mod.run(target, ctx)
    http.close()
    httpd.shutdown()
    assert findings
    assert findings[0].confidence >= 0.9