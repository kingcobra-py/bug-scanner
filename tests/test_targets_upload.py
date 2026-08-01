from pathlib import Path

from fastapi.testclient import TestClient

from app.api.server import create_app
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
    app = create_app()
    client = TestClient(app)
    files = {"file": ("hosts.txt", b"alpha.test\nbeta.test\n#skip\nalpha.test\n", "text/plain")}
    res = client.post("/api/targets/upload", files=files)
    assert res.status_code == 200
    data = res.json()
    assert data["count"] == 2
    assert data["targets"] == ["alpha.test", "beta.test"]
    assert "alpha.test" in data["targets_text"]
