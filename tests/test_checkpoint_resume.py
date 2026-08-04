"""Durable checkpoints and resume-after-reboot behavior."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import server
from app.api.server import create_app, _resume_scan, _scan_config_from_dict
from app.core.checkpoint import (
    CheckpointWriter,
    append_completed_index,
    iter_indexed_targets,
    load_completed_indices,
)
from app.core.engine import ScanEngine
from app.core.progress import ProgressManager
from app.storage.db import ScanStore
from app.storage.models import ScanConfig


def test_checkpoint_roundtrip(tmp_path):
    out = tmp_path / "scan"
    out.mkdir()
    append_completed_index(out, 0)
    append_completed_index(out, 3)
    writer = CheckpointWriter(out)
    writer.mark(7)
    assert load_completed_indices(out) == {0, 3, 7}


def test_iter_indexed_targets_skips_completed():
    targets = ["a.example", "b.example", "c.example"]
    remaining = list(iter_indexed_targets(targets, skip={1}))
    assert remaining == [(0, "https://a.example"), (2, "https://c.example")]


def test_seed_completed_progress():
    progress = ProgressManager(enable_cli=False)
    progress.start(100)
    progress.seed_completed(40)
    snap = progress.snapshot()
    assert snap.done == 40
    assert snap.percent == 40.0


def test_create_scan_preserves_progress_on_resume(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    out = tmp_path / "scan-r"
    out.mkdir()
    store.create_scan("scan-r", {"job_name": "R", "modules": ["git"], "target_count": 10}, str(out))
    store.update_progress("scan-r", {"total": 10, "done": 4, "failed": 0, "percent": 40.0})
    store.update_status("scan-r", "stopped")
    store.create_scan("scan-r", {"job_name": "R", "modules": ["git"], "target_count": 10}, str(out))
    row = store.get_scan("scan-r")
    assert row["progress"]["done"] == 4
    assert row["status"] == "stopped"


def test_rebuild_scan_config_uses_targets_file(tmp_path):
    store = ScanStore(tmp_path / "scanner.db")
    out = tmp_path / "scans" / "scan-b"
    out.mkdir(parents=True)
    (out / "targets.txt").write_text("a.example\nb.example\n", encoding="utf-8")
    store.create_scan(
        "scan-b",
        {"job_name": "B", "modules": ["git"], "target_count": 2, "threads": 12},
        str(out),
    )
    rebuilt = store.rebuild_scan_config("scan-b")
    assert rebuilt is not None
    assert rebuilt["scan_id"] == "scan-b"
    assert rebuilt["targets_path"].endswith("targets.txt")
    assert rebuilt["threads"] == 12
    cfg = _scan_config_from_dict(rebuilt)
    assert cfg.scan_id == "scan-b"
    assert cfg.targets_path.endswith("targets.txt")


def test_resume_api_restarts_from_checkpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ROOT", tmp_path)
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    store = ScanStore(tmp_path / "scanner.db")
    monkeypatch.setattr(server, "store", store)
    engine = ScanEngine(store=store, enable_cli_progress=False)
    monkeypatch.setattr(server, "engine", engine)

    scan_id = "resume-api"
    out = tmp_path / "output" / "scans" / scan_id
    out.mkdir(parents=True)
    (out / "targets.txt").write_text("a.example\nb.example\nc.example\n", encoding="utf-8")
    append_completed_index(out, 0)
    store.create_scan(
        scan_id,
        {
            "job_name": "Resume me",
            "modules": ["git"],
            "target_count": 3,
            "threads": 2,
            "worker_processes": 1,
            "timeout": 2,
            "retries": 0,
            "rate_limit_per_host": 10,
            "paths_mode": "builtin_only",
            "output_dir": str(tmp_path / "output" / "scans"),
            "scan_id": scan_id,
        },
        str(out),
    )
    store.update_status(scan_id, "stopped")
    store.update_progress(scan_id, {"total": 3, "done": 1, "failed": 0, "percent": 33.3})

    started = []

    def fake_start(cfg: ScanConfig) -> str:
        started.append(cfg)
        return cfg.scan_id

    monkeypatch.setattr(engine, "start_async", fake_start)

    client = TestClient(create_app())
    response = client.post(f"/api/scans/{scan_id}/resume")
    assert response.status_code == 200
    assert response.json()["resumed"] is True
    assert started and started[0].scan_id == scan_id
    assert started[0].targets_path.endswith("targets.txt")
    assert load_completed_indices(out) == {0}


def test_resume_rejects_completed(tmp_path, monkeypatch):
    store = ScanStore(tmp_path / "scanner.db")
    monkeypatch.setattr(server, "store", store)
    monkeypatch.setattr(server, "engine", ScanEngine(store=store, enable_cli_progress=False))
    out = tmp_path / "done"
    out.mkdir()
    (out / "targets.txt").write_text("a.example\n", encoding="utf-8")
    store.create_scan("done-1", {"modules": ["git"], "target_count": 1}, str(out))
    store.update_status("done-1", "completed")
    try:
        _resume_scan("done-1")
        assert False, "expected HTTPException"
    except Exception as exc:
        assert getattr(exc, "status_code", None) == 400
