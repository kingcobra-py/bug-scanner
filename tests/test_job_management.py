from fastapi.testclient import TestClient

from app.api import server
from app.api.server import create_app
from app.core.engine import ScanEngine
from app.storage.db import ScanStore


def test_compact_scan_list_omits_large_arrays(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    store.create_scan(
        "scan-1",
        {
            "job_name": "Compact job",
            "targets": ["a.example", "b.example"],
            "custom_paths": ["/.env", "/config"],
            "modules": ["git"],
        },
        str(tmp_path / "scan-1"),
    )

    full = store.list_scans(compact=False)[0]
    compact = store.list_scans(compact=True)[0]

    assert full["config"]["targets"] == ["a.example", "b.example"]
    assert "targets" not in compact["config"]
    assert "custom_paths" not in compact["config"]
    assert compact["config"]["target_count"] == 2
    assert compact["config"]["custom_path_count"] == 2


def test_compact_scan_list_keeps_precomputed_counts(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    store.create_scan(
        "scan-slim",
        {
            "job_name": "Slim job",
            "modules": ["git"],
            "target_count": 6343,
            "custom_path_count": 12,
        },
        str(tmp_path / "scan-slim"),
    )

    compact = store.list_scans(compact=True)[0]
    assert "targets" not in compact["config"]
    assert compact["config"]["target_count"] == 6343
    assert compact["config"]["custom_path_count"] == 12


def test_compact_scan_list_slims_fat_summaries(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    store.create_scan("scan-fat", {"modules": ["git"], "target_count": 2}, str(tmp_path / "scan-fat"))
    store.update_summary(
        "scan-fat",
        {
            "finding_count": 3,
            "targets": ["a.example"] * 1000,
            "by_severity": {"high": 3},
        },
    )

    full = store.list_scans(compact=False)[0]
    compact = store.list_scans(compact=True)[0]
    assert len(full["summary"]["targets"]) == 1000
    assert "targets" not in compact["summary"]
    assert compact["summary"]["finding_count"] == 3
    assert compact["summary"]["target_count"] == 1000
    assert store.slim_stored_summaries() >= 1
    rewritten = store.get_scan("scan-fat", compact=False)
    assert "targets" not in rewritten["summary"]


def test_findings_are_newest_first(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    store.create_scan("scan-order", {"targets": ["a.example"]}, str(tmp_path / "scan-order"))
    store.add_finding(
        "scan-order",
        {
            "id": "old",
            "type": "path",
            "severity": "low",
            "target": "https://a.example",
            "url": "https://a.example/old",
            "title": "Old hit",
            "timestamp": "2026-08-01T10:00:00+00:00",
        },
    )
    store.add_finding(
        "scan-order",
        {
            "id": "new",
            "type": "path",
            "severity": "high",
            "target": "https://a.example",
            "url": "https://a.example/new",
            "title": "New hit",
            "timestamp": "2026-08-01T20:00:00+00:00",
        },
    )
    rows = store.get_findings("scan-order")
    assert [row["id"] for row in rows] == ["new", "old"]


def test_orphaned_running_job_can_be_stopped_and_deleted(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    store.create_scan("scan-2", {"targets": ["a.example"]}, str(tmp_path / "scan-2"))
    store.update_status("scan-2", "running")
    engine = ScanEngine(store=store, enable_cli_progress=False)

    assert engine.stop("scan-2") is True
    assert store.get_scan("scan-2")["status"] == "stopped"
    assert store.delete_scan("scan-2") is True
    assert store.get_scan("scan-2") is None


def test_delete_scan_removes_related_findings_and_logs(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    store.create_scan("scan-3", {"targets": ["a.example"]}, str(tmp_path / "scan-3"))
    store.add_finding(
        "scan-3",
        {
            "id": "finding-1",
            "type": "path",
            "severity": "high",
            "target": "https://a.example",
            "url": "https://a.example/.env",
            "title": "Exposed env",
        },
    )
    store.add_log("scan-3", {"message": "scan started"})

    assert store.delete_scan("scan-3") is True
    assert store.get_findings("scan-3") == []
    assert store.get_logs("scan-3") == []


def test_archive_job_hides_card_but_preserves_results(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    store.create_scan("scan-4", {"targets": ["a.example"]}, str(tmp_path / "scan-4"))
    store.update_status("scan-4", "completed")
    store.add_finding(
        "scan-4",
        {
            "id": "finding-4",
            "type": "js_secret",
            "severity": "critical",
            "target": "https://a.example",
            "url": "https://a.example/app.js",
            "title": "API key",
        },
    )

    assert store.archive_scan("scan-4") is True
    assert store.list_scans() == []
    archived = store.list_scans(include_archived=True)
    assert archived[0]["archived"] is True
    assert store.get_findings("scan-4")[0]["id"] == "finding-4"


def test_get_results_does_not_rewrite_vuln_artifacts(tmp_path, monkeypatch):
    # Results is polled on every provider-filter click; regenerating the
    # on-disk vulns/ tree there made filtering feel slow.
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    client = TestClient(create_app())
    scan_id = "results-perf-test"
    out_dir = tmp_path / "scan-out"
    server.store.create_scan(scan_id, {"targets": ["a.example"]}, str(out_dir))
    server.store.add_finding(
        scan_id,
        {
            "id": "f1",
            "type": "js_secret",
            "severity": "high",
            "target": "https://a.example",
            "url": "https://a.example/app.js",
            "title": "Secret in JS",
            "module": "js",
            "extracted": {"secrets": [{"kind": "github_token", "value": "ghp_x"}]},
        },
    )

    response = client.get(f"/api/scans/{scan_id}/results")
    assert response.status_code == 200
    data = response.json()
    assert data["finding_count"] == 1
    assert "findings" not in data
    assert not (out_dir / "vulns").exists()

    compact = client.get(
        f"/api/scans/{scan_id}/results",
        params={"include_findings": True},
    ).json()
    assert compact["findings"][0]["id"] == "f1"
    assert "evidence" not in compact["findings"][0]
    assert "extracted" not in compact["findings"][0]

    detail = client.get(f"/api/scans/{scan_id}/findings/f1")
    assert detail.status_code == 200
    assert detail.json()["extracted"]["secrets"][0]["kind"] == "github_token"
    server.store.delete_scan(scan_id)


def test_purge_job_deletes_database_results_and_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ROOT", tmp_path)
    client = TestClient(create_app())
    scan_id = "purge-results-test"
    out_dir = tmp_path / "output" / "scans" / scan_id
    out_dir.mkdir(parents=True)
    (out_dir / "report.json").write_text("{}", encoding="utf-8")
    server.store.create_scan(scan_id, {"targets": ["a.example"]}, str(out_dir))
    server.store.update_status(scan_id, "stopped")
    server.store.add_finding(
        scan_id,
        {
            "id": "purge-finding",
            "type": "path",
            "severity": "high",
            "target": "https://a.example",
            "url": "https://a.example/.env",
            "title": "Purge me",
        },
    )
    server.store.add_log(scan_id, {"message": "purge me"})

    response = client.delete(f"/api/scans/{scan_id}/purge")
    assert response.status_code == 200
    assert response.json()["purged"] is True
    assert server.store.get_scan(scan_id) is None
    assert server.store.get_findings(scan_id) == []
    assert server.store.get_logs(scan_id) == []
    assert not out_dir.exists()
