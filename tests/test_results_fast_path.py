"""Results must not load every finding row for secret/summary aggregation."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import server
from app.api.server import create_app


def test_results_uses_secret_candidates_not_full_table(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    # Bust any process-global Results cache from earlier tests.
    server._RESULTS_CACHE.clear()
    client = TestClient(create_app())
    scan_id = "results-fast-path"
    out_dir = tmp_path / "scan-out"
    server.store.create_scan(scan_id, {"targets": ["a.example"]}, str(out_dir))

    # Noise: empty extracted blobs (the shape that dominated million-row scans).
    for i in range(80):
        server.store.add_finding(
            scan_id,
            {
                "id": f"noise-{i}",
                "type": "path",
                "severity": "info",
                "target": f"https://noise-{i}.example",
                "url": f"https://noise-{i}.example/",
                "title": "path hit",
                "module": "path",
                "extracted": {"secrets": [], "apis": [], "smtp": [], "endpoints": []},
            },
        )

    server.store.add_finding(
        scan_id,
        {
            "id": "secret-1",
            "type": "env",
            "severity": "high",
            "target": "https://a.example",
            "url": "https://a.example/.env",
            "title": "env secrets",
            "module": "config",
            "extracted": {
                "secrets": [
                    {
                        "kind": "env",
                        "value": "STRIPE_SECRET_KEY=sk_live_fastpath_test_value",
                        "source_url": "https://a.example/.env",
                    }
                ]
            },
        },
    )

    candidates = server.store.get_secret_candidate_findings(scan_id)
    assert len(candidates) == 1
    assert candidates[0]["id"] == "secret-1"

    stats = server.store.finding_stats(scan_id)
    assert stats["finding_count"] == 81
    assert stats["by_module"].get("path") == 80

    data = client.get(f"/api/scans/{scan_id}/results").json()
    assert data["finding_count"] == 81
    assert any("sk_live_fastpath_test_value" in item["value"] for item in data["secrets"])
    server.store.delete_scan(scan_id)
