from pathlib import Path

from fastapi.testclient import TestClient

from app.api import server
from app.api.server import create_app
from app.core import uploads
from app.core.providers import provider_for_kind, provider_metadata
from app.core.wordlists import parse_target_lines, save_uploaded_targets


def test_parse_target_lines():
    text = """
    # comment
    example.com
    1.2.3.4
    https://app.example.com
    example.com
    host.local # note
    """
    targets = parse_target_lines(text)
    assert targets == ["example.com", "1.2.3.4", "https://app.example.com", "host.local"]


def test_save_uploaded_targets(tmp_path):
    dest = tmp_path / "targets.txt"
    out = save_uploaded_targets(b"a.com\nb.com\n#x\na.com\n", dest)
    assert out == ["a.com", "b.com"]
    assert dest.read_text().strip().splitlines() == ["a.com", "b.com"]


def test_targets_upload_api(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    app = create_app()
    client = TestClient(app)
    files = {"file": ("hosts.txt", b"alpha.test\nbeta.test\n#skip\nalpha.test\n", "text/plain")}
    res = client.post("/api/targets/upload", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 2
    assert data["targets"] == ["alpha.test", "beta.test"]
    assert "alpha.test" in data["targets_text"]


def test_persistent_upload_library_and_job_reference(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    started = []
    monkeypatch.setattr(server.engine, "start_async", lambda config: started.append(config))
    monkeypatch.setattr(
        server,
        "read_upload_items",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("job creation must not parse upload")),
    )
    client = TestClient(create_app())

    uploaded = client.post(
        "/api/uploads",
        data={"kind": "targets"},
        files={"file": ("scope.txt", b"a.example\nb.example\na.example\n", "text/plain")},
    )
    assert uploaded.status_code == 200
    record = uploaded.json()
    assert record["item_count"] == 2
    assert Path(record["stored_path"]).is_file()

    rows = client.get("/api/uploads", params={"kind": "targets"}).json()
    assert any(row["id"] == record["id"] and row["exists"] for row in rows)

    created = client.post(
        "/api/scans",
        json={
            "job_name": "Uploaded scope",
            "targets_upload_id": record["id"],
            "threads": 17,
            "modules": ["git", "js"],
        },
    )
    assert created.status_code == 200
    body = created.json()
    assert body["id"]
    assert started
    # Upload-backed jobs start immediately by file reference; the 500MB file
    # is streamed later by the engine instead of parsed inside POST /api/scans.
    assert started[0].targets == []
    assert Path(started[0].targets_path).is_file()
    assert started[0].target_count == 2
    assert started[0].job_name == "Uploaded scope"
    assert started[0].targets_upload_id == record["id"]
    pending = client.get("/api/scans", params={"compact": True}).json()
    assert any(row["id"] == body["id"] and row["config"]["target_count"] == 2 for row in pending)

    deleted = client.delete(f"/api/uploads/{record['id']}")
    assert deleted.status_code == 200
    assert not Path(record["stored_path"]).exists()


def test_chunked_upload_progress_resume_and_download(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    monkeypatch.setattr(uploads, "CHUNK_SIZE", 4)
    client = TestClient(create_app())
    content = b"http://one.example\nhttps://two.example\n"

    init = client.post(
        "/api/uploads/chunks/init",
        json={"filename": "large targets.txt", "kind": "targets", "total_size": len(content)},
    )
    assert init.status_code == 200
    session = init.json()
    assert session["chunk_size"] == 4
    upload_id = session["id"]

    # Upload out of order to exercise parallel/resumable chunks.
    chunks = [content[i : i + 4] for i in range(0, len(content), 4)]
    last = len(chunks) - 1
    for index in [last, *range(last)]:
        response = client.put(
            f"/api/uploads/chunks/{upload_id}/{index}",
            content=chunks[index],
            headers={"Content-Type": "application/octet-stream"},
        )
        assert response.status_code == 200

    status = client.get(f"/api/uploads/chunks/{upload_id}")
    assert status.status_code == 200
    assert status.json()["received_bytes"] == len(content)
    assert len(status.json()["received_chunks"]) == len(chunks)

    complete = client.post(f"/api/uploads/chunks/{upload_id}/complete")
    assert complete.status_code == 200
    record = complete.json()
    assert record["original_name"] == "large_targets.txt"
    assert record["size_bytes"] == len(content)
    assert record["item_count"] == 2

    download = client.get(f"/api/uploads/{upload_id}/download")
    assert download.status_code == 200
    assert download.content == content
    assert "large_targets.txt" in download.headers["content-disposition"]


def test_chunk_upload_rejects_over_5gb(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    client = TestClient(create_app())
    response = client.post(
        "/api/uploads/chunks/init",
        json={
            "filename": "too-large.txt",
            "kind": "targets",
            "total_size": uploads.MAX_UPLOAD_BYTES + 1,
        },
    )
    assert response.status_code == 400
    assert "5 GB" in response.json()["detail"]


def test_provider_kind_mapping():
    assert provider_for_kind("aws_access_key") == "aws"
    assert provider_for_kind("stripe_live") == "stripe"
    assert provider_for_kind("github_token") == "github"
    assert provider_for_kind("unknown_vendor_key") == "generic"
    assert provider_metadata("twilio")["logo"] == "/static/img/providers/twilio.svg"
    assert provider_metadata("sendgrid")["logo"] == "/static/img/providers/sendgrid.png"
