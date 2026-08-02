"""Pagination for Results tables: findings + vulnerable hosts."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import server
from app.api.server import create_app


def _seed_scan(tmp_path, monkeypatch, scan_id: str, finding_count: int = 45):
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    # Reuse the process-global store but always use a unique scan_id so
    # tests do not collide with leftovers from earlier cases.
    client = TestClient(create_app())
    out_dir = tmp_path / f"scan-out-{scan_id}"
    server.store.create_scan(scan_id, {"targets": ["a.example"]}, str(out_dir))
    for i in range(finding_count):
        server.store.add_finding(
            scan_id,
            {
                "id": f"{scan_id}-f{i}",
                "type": "path",
                "severity": "high" if i % 2 == 0 else "medium",
                "target": f"https://host-{i}.example",
                "url": f"https://host-{i}.example/.env",
                "title": f"Hit {i}",
                "module": "config" if i % 3 == 0 else "wordpress",
                "timestamp": f"2026-08-02T{10 + (i // 60):02d}:{i % 60:02d}:00+00:00",
                "tags": ["detection-only"],
                "evidence": f"body-{i}",
            },
        )
    return client, scan_id


def test_findings_endpoint_returns_paginated_envelope(tmp_path, monkeypatch):
    client, scan_id = _seed_scan(tmp_path, monkeypatch, "page-findings", finding_count=45)

    page1 = client.get(
        f"/api/scans/{scan_id}/findings",
        params={"page": 1, "page_size": 10},
    ).json()
    assert page1["total"] == 45
    assert page1["page"] == 1
    assert page1["page_size"] == 10
    assert page1["pages"] == 5
    assert len(page1["items"]) == 10
    # Newest first.
    assert page1["items"][0]["id"] == f"{scan_id}-f44"

    page5 = client.get(
        f"/api/scans/{scan_id}/findings",
        params={"page": 5, "page_size": 10},
    ).json()
    assert len(page5["items"]) == 5
    assert page5["page"] == 5

    filtered = client.get(
        f"/api/scans/{scan_id}/findings",
        params={"page": 1, "page_size": 20, "module": "config"},
    ).json()
    assert filtered["total"] == 15  # 0,3,6,...,42
    assert all(item["module"] == "config" for item in filtered["items"])
    assert filtered["page_size"] == 20


def test_findings_page_size_capped_at_100(tmp_path, monkeypatch):
    client, scan_id = _seed_scan(tmp_path, monkeypatch, "page-cap", finding_count=5)
    data = client.get(
        f"/api/scans/{scan_id}/findings",
        params={"page": 1, "page_size": 1000},
    ).json()
    assert data["page_size"] == 100
    assert data["total"] == 5


def test_results_hosts_are_paginated(tmp_path, monkeypatch):
    client, scan_id = _seed_scan(tmp_path, monkeypatch, "page-hosts", finding_count=25)

    page1 = client.get(
        f"/api/scans/{scan_id}/results",
        params={"hosts_page": 1, "hosts_page_size": 10},
    ).json()
    assert page1["vulnerable_host_count"] == 25
    assert page1["hosts_page"] == 1
    assert page1["hosts_page_size"] == 10
    assert page1["hosts_pages"] == 3
    assert len(page1["vulnerable_hosts"]) == 10
    assert "findings" not in page1

    page3 = client.get(
        f"/api/scans/{scan_id}/results",
        params={"hosts_page": 3, "hosts_page_size": 10},
    ).json()
    assert len(page3["vulnerable_hosts"]) == 5
    assert page3["hosts_page"] == 3
