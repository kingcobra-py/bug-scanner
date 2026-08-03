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
    assert any("sendgrid" in item["value"].lower() for item in data["secrets"])
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
                    {"kind": "env", "value": "AWS_SECRET_ACCESS_KEY=super-secret", "source_url": "https://a.example"},
                ]
            },
        },
    )

    data = client.get(f"/api/scans/{scan_id}/results").json()
    assert any("super-secret" in item["value"] for item in data["secrets"])
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
            "evidence": "DB_PASSWORD=legacy-password\nAPP_KEY=legacy-key",
        },
    )

    data = client.get(f"/api/scans/{scan_id}/results").json()
    values = {item["value"] for item in data["secrets"]}
    assert "DB_PASSWORD=legacy-password" in values
    assert "APP_KEY=legacy-key" in values
    server.store.delete_scan(scan_id)
