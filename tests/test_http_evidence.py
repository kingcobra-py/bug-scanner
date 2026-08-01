from pathlib import Path
from types import SimpleNamespace

from app.core.http_client import HttpResponse
from app.core.vuln_artifacts import write_vuln_artifacts
from app.modules.base import format_http_response, save_http_response, save_method_responses
from app.storage.models import ScanConfig, ScanContext


def _ctx(tmp_path: Path) -> ScanContext:
    cfg = ScanConfig(targets=["https://example.test"], output_dir=str(tmp_path))
    return ScanContext(
        config=cfg,
        output_dir=tmp_path / "scan",
        stop_event=SimpleNamespace(is_set=lambda: False),
        progress=SimpleNamespace(),
        store=None,
        http=None,
    )


def test_save_http_response_writes_full_transcript(tmp_path):
    ctx = _ctx(tmp_path)
    resp = HttpResponse(
        url="https://example.test/.env",
        status_code=200,
        headers={"content-type": "text/plain", "server": "nginx"},
        text="AWS_ACCESS_KEY_ID=AKIATEST\nSECRET=1\n",
        content=b"AWS_ACCESS_KEY_ID=AKIATEST\nSECRET=1\n",
        elapsed=0.12,
        method="GET",
    )
    path = Path(save_http_response(ctx, "config__.env", resp))
    assert path.suffix == ".http"
    text = path.read_text(encoding="utf-8")
    assert "GET https://example.test/.env HTTP/1.1" in text
    assert "HTTP/1.1 200" in text
    assert "content-type: text/plain" in text
    assert "AWS_ACCESS_KEY_ID=AKIATEST" in text
    assert path.with_suffix(".txt").exists()


def test_save_method_responses_bundle(tmp_path):
    ctx = _ctx(tmp_path)
    results = [
        HttpResponse(
            url="https://api.example.test/upload",
            status_code=200,
            headers={"allow": "GET, PUT, DELETE"},
            text="ok",
            content=b"ok",
            elapsed=0.01,
            method="GET",
        ),
        HttpResponse(
            url="https://api.example.test/upload",
            status_code=201,
            headers={"content-type": "text/plain"},
            text="created",
            content=b"created",
            elapsed=0.02,
            method="PUT",
        ),
        HttpResponse(
            url="https://api.example.test/upload",
            status_code=204,
            headers={},
            text="",
            content=b"",
            elapsed=0.02,
            method="DELETE",
        ),
    ]
    summary = Path(save_method_responses(ctx, "methods_api.example.test_upload", "https://api.example.test/upload", results))
    bundle = summary.parent
    assert summary.name == "SUMMARY.txt"
    assert (bundle / "GET.http").exists()
    assert (bundle / "PUT.http").exists()
    assert (bundle / "DELETE.http").exists()
    put = (bundle / "PUT.http").read_text(encoding="utf-8")
    assert "HTTP/1.1 201" in put
    assert "created" in put


def test_vuln_artifacts_copy_method_bundle_and_http(tmp_path):
    evid = tmp_path / "evidence"
    evid.mkdir()
    http_file = evid / "config__.env.http"
    http_file.write_text(
        format_http_response(
            HttpResponse(
                url="https://env.victim.test/.env",
                status_code=200,
                headers={"content-type": "text/plain"},
                text="KEY=1\n",
                content=b"KEY=1\n",
                elapsed=0.1,
                method="GET",
            )
        ),
        encoding="utf-8",
    )
    (evid / "config__.env.txt").write_text("KEY=1\n", encoding="utf-8")

    methods_dir = evid / "methods_api.victim.test_api"
    methods_dir.mkdir()
    (methods_dir / "SUMMARY.txt").write_text("URL: https://api.victim.test/api\n", encoding="utf-8")
    (methods_dir / "PUT.http").write_text("PUT ...\nHTTP/1.1 201\n\nok\n", encoding="utf-8")

    findings = [
        {
            "id": "e1",
            "module": "config",
            "target": "https://env.victim.test",
            "url": "https://env.victim.test/.env",
            "title": "Exposed .env",
            "severity": "critical",
            "type": "env",
            "tags": ["env"],
            "confidence": 0.95,
            "evidence": "KEY=",
            "raw_ref": str(http_file),
            "extracted": {},
        },
        {
            "id": "m1",
            "module": "methods",
            "target": "https://api.victim.test",
            "url": "https://api.victim.test/api",
            "title": "Unexpected HTTP methods accepted",
            "severity": "medium",
            "type": "other",
            "tags": ["methods"],
            "confidence": 0.7,
            "evidence": "interesting=[PUT:201]",
            "raw_ref": str(methods_dir / "SUMMARY.txt"),
            "extracted": {},
        },
    ]
    bundle = write_vuln_artifacts(tmp_path, findings)
    vulns = Path(bundle["dir"])
    assert any(p.name.endswith(".http") for p in (vulns / "env").glob("*"))
    assert any(p.name.endswith(".txt") for p in (vulns / "env").glob("*"))
    method_dirs = [p for p in (vulns / "methods").iterdir() if p.is_dir() and "methods__" in p.name]
    assert method_dirs
    assert (method_dirs[0] / "PUT.http").exists()
