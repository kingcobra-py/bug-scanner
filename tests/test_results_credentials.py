from fastapi.testclient import TestClient

from app.api import server
from app.api.server import create_app


def test_get_results_includes_smtp_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    client = TestClient(create_app())
    scan_id = "results-smtp-test"
    out_dir = tmp_path / "scan-out"
    server.store.create_scan(scan_id, {"targets": ["a.example"]}, str(out_dir))
    server.store.add_finding(
        scan_id,
        {
            "id": "smtp-1",
            "type": "smtp",
            "severity": "critical",
            "target": "https://a.example",
            "url": "https://a.example/.env",
            "title": "SMTP credentials extracted",
            "module": "config",
            "timestamp": "2026-08-04T12:34:56+00:00",
            "extracted": {
                "smtp": [
                    {
                        "kind": "smtp",
                        "value": {
                            "host": "smtp.sendgrid.net",
                            "port": "587",
                            "user": "apikey",
                            "pass": "SG.test-secret",
                        },
                    }
                ]
            },
        },
    )

    data = client.get(f"/api/scans/{scan_id}/results").json()
    assert data["secrets"]
    match = next(item for item in data["secrets"] if "sendgrid" in item["value"].lower())
    assert match["module"] == "config"
    assert "config" in (match.get("modules") or [])
    assert match["timestamp"].startswith("2026-08-04T12:34:56")
    server.store.delete_scan(scan_id)


def test_get_results_includes_exploit_extracted_secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    client = TestClient(create_app())
    scan_id = "results-exploit-test"
    out_dir = tmp_path / "scan-out"
    server.store.create_scan(scan_id, {"targets": ["a.example"]}, str(out_dir))
    server.store.add_finding(
        scan_id,
        {
            "id": "exploit-1",
            "type": "secrets",
            "severity": "high",
            "target": "https://a.example",
            "url": "https://a.example",
            "title": "Secret extraction: env (React2Shell)",
            "module": "react2shell",
            "extracted": {
                    "secrets": [
                    {
                        "kind": "env",
                        "value": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                        "source_url": "https://a.example",
                    },
                    {
                        "kind": "env",
                        "value": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
                        "source_url": "https://a.example",
                    },
                ]
            },
        },
    )

    data = client.get(f"/api/scans/{scan_id}/results").json()
    assert any(
        "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" in item["value"]
        for item in data["secrets"]
    )
    server.store.delete_scan(scan_id)


def test_get_results_legacy_exploit_evidence_fallback(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    client = TestClient(create_app())
    scan_id = "results-legacy-exploit"
    out_dir = tmp_path / "scan-out"
    server.store.create_scan(scan_id, {"targets": ["a.example"]}, str(out_dir))
    server.store.add_finding(
        scan_id,
        {
            "id": "legacy-1",
            "type": "secrets",
            "severity": "high",
            "target": "https://a.example",
            "url": "https://a.example",
            "title": "Secret extraction: env (wp2shell)",
            "module": "wordpress",
            "evidence": "DB_PASSWORD=legacy-password\nAPP_KEY=legacy-key\n1819577869\n#1654678059",
        },
    )

    data = client.get(f"/api/scans/{scan_id}/results").json()
    values = {item["value"] for item in data["secrets"]}
    # Generic env leftovers are filtered; timestamps must never appear.
    assert "DB_PASSWORD=legacy-password" not in values
    assert "APP_KEY=legacy-key" not in values
    assert "1819577869" not in values
    assert "#1654678059" not in values
    server.store.delete_scan(scan_id)
