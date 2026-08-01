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
