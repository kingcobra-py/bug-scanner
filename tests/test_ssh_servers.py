"""SSH server registry API and store helpers."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.api import server
from app.api.server import create_app
from app.core.ssh_servers import SshServer, SshServerStore, public_server_dict


def test_ssh_store_crud(tmp_path):
    store = SshServerStore(tmp_path / "ssh_servers.json")
    server_row = SshServer(
        id="abc123",
        host="ec2.example.com",
        port=22,
        username="ubuntu",
        private_key="KEYDATA",
        label="node-a",
    )
    store.upsert(server_row)
    listed = store.list()
    assert len(listed) == 1
    assert listed[0].host == "ec2.example.com"
    assert store.get("abc123").private_key == "KEYDATA"
    assert store.delete("abc123") is True
    assert store.list() == []


def test_public_server_dict_redacts_secrets():
    server_row = SshServer(
        id="x",
        host="h.example",
        private_key="SECRETKEY",
        password="pw",
    )
    public = public_server_dict(server_row)
    assert public["private_key"] == "***"
    assert public["password"] == "***"
    assert public["has_key"] is True
    assert public["has_password"] is True
    assert public["endpoint"] == "h.example:22"


def test_create_job_requires_ready_ssh_servers(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ROOT", tmp_path)
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    ssh_store = SshServerStore(tmp_path / "ssh.json")
    monkeypatch.setattr(server, "ssh_store", ssh_store)

    from app.core.ssh_servers import SshServer, new_server_id

    sid = new_server_id()
    ssh_store.upsert(SshServer(id=sid, host="node.example", private_key="KEY", label="node-a"))

    started = []
    monkeypatch.setattr(server.engine, "start_async", lambda config: started.append(config))
    monkeypatch.setattr(
        server,
        "preflight_servers",
        lambda _store, ids: [{
            "id": sid,
            "host": "node.example",
            "endpoint": "node.example:22",
            "label": "node-a",
            "auth_type": "key",
            "ok": False,
            "online": False,
            "echo_ok": False,
            "hostname": "",
            "error": "connection refused",
            "metrics": {},
        }],
    )

    client = TestClient(create_app())
    uploaded = client.post(
        "/api/uploads",
        data={"kind": "targets"},
        files={"file": ("scope.txt", b"a.example\n", "text/plain")},
    )
    assert uploaded.status_code == 200
    upload_id = uploaded.json()["id"]

    bad = client.post(
        "/api/scans",
        json={
            "job_name": "ssh fail",
            "targets_upload_id": upload_id,
            "modules": ["git"],
            "ssh_server_ids": [sid],
            "threads": 2,
        },
    )
    assert bad.status_code == 400
    assert "not ready" in bad.json()["detail"].lower()
    assert started == []

    monkeypatch.setattr(
        server,
        "preflight_servers",
        lambda _store, ids: [{
            "id": sid,
            "host": "node.example",
            "endpoint": "node.example:22",
            "label": "node-a",
            "auth_type": "key",
            "ok": True,
            "online": True,
            "echo_ok": True,
            "hostname": "node-a",
            "error": "",
            "metrics": {"cpu_percent": 1},
        }],
    )
    ok = client.post(
        "/api/scans",
        json={
            "job_name": "ssh ok",
            "targets_upload_id": upload_id,
            "modules": ["git"],
            "ssh_server_ids": [sid],
            "threads": 2,
        },
    )
    assert ok.status_code == 200
    body = ok.json()
    assert body["ssh_server_ids"] == [sid]
    assert body["ssh_preflight"][0]["ok"] is True
    assert started
    scan = server.store.get_scan(body["id"])
    assert scan["config"]["ssh_servers"][0]["label"] == "node-a"


def test_servers_api_accepts_password_auth(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ROOT", tmp_path)
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    monkeypatch.setattr(server, "ssh_store", SshServerStore(tmp_path / "ssh.json"))
    monkeypatch.setattr(
        server,
        "collect_metrics",
        lambda srv: {
            "online": True,
            "error": "",
            "cpu_percent": 1,
            "memory_percent": 2,
            "disk_percent": 3,
            "cores": 2,
            "load": "0.1",
            "procs": 10,
            "net": "1k/1k",
        },
    )
    client = TestClient(create_app())
    missing = client.post(
        "/api/servers",
        json={"host": "h.example", "auth_type": "password", "username": "root"},
    )
    assert missing.status_code == 400
    created = client.post(
        "/api/servers",
        json={
            "host": "h.example",
            "auth_type": "password",
            "username": "root",
            "password": "s3cret",
        },
    )
    assert created.status_code == 200
    body = created.json()
    assert body["auth_type"] == "password"
    assert body["password"] == "***"
    assert body["has_password"] is True
    assert body["has_key"] is False
    stored = server.ssh_store.get(body["id"])
    assert stored.password == "s3cret"
    assert stored.private_key == ""


def test_servers_api_crud_and_metrics(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ROOT", tmp_path)
    monkeypatch.setattr(server, "UPLOAD_DIR", tmp_path / "uploads")
    ssh_store = SshServerStore(tmp_path / "output" / "ssh_servers.json")
    monkeypatch.setattr(server, "ssh_store", ssh_store)

    def fake_metrics(srv):
        return {
            "online": True,
            "error": "",
            "cpu_percent": 12.5,
            "memory_percent": 40.0,
            "disk_percent": 55.0,
            "cores": 4,
            "load": "0.50",
            "procs": 120,
            "net": "10k/2k",
        }

    def fake_install(srv):
        return {
            "ok": True,
            "exit_code": 0,
            "stdout": "OK",
            "stderr": "",
            "message": "Dependencies installed",
        }

    monkeypatch.setattr(server, "collect_metrics", fake_metrics)
    monkeypatch.setattr(server, "install_deps", fake_install)

    client = TestClient(create_app())
    created = client.post(
        "/api/servers",
        json={
            "host": "ec2-32-198-65-6.compute-1.amazonaws.com",
            "port": 22,
            "username": "ubuntu",
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----",
            "label": "fleet-1",
        },
    )
    assert created.status_code == 200
    body = created.json()
    assert body["status"] == "online"
    assert body["private_key"] == "***"
    assert body["metrics"]["cpu_percent"] == 12.5
    server_id = body["id"]

    listed = client.get("/api/servers").json()
    assert len(listed) == 1
    assert listed[0]["id"] == server_id

    metrics = client.post(f"/api/servers/{server_id}/metrics").json()
    assert metrics["status"] == "online"
    assert metrics["metrics"]["cores"] == 4

    installed = client.post(f"/api/servers/{server_id}/install-deps").json()
    assert installed["ok"] is True
    assert installed["server"]["id"] == server_id

    deleted = client.delete(f"/api/servers/{server_id}")
    assert deleted.status_code == 200
    assert client.get("/api/servers").json() == []


def test_friendly_ssh_error_messages():
    from app.core.ssh_servers import friendly_ssh_error

    assert "resolve hostname" in friendly_ssh_error(
        "ssh: Could not resolve hostname ec2-x: Temporary failure in name resolution"
    ).lower()
    assert "timed out" in friendly_ssh_error("ssh timeout").lower()
    assert "auth failed" in friendly_ssh_error("Permission denied (publickey).").lower()


def test_store_preserves_last_install(tmp_path):
    store = SshServerStore(tmp_path / "ssh_servers.json")
    store.upsert(
        SshServer(
            id="n1",
            host="h.example",
            private_key="KEY",
            last_install={"ok": True, "message": "Dependencies installed", "at": "2026-08-04T22:00:00+00:00"},
        )
    )
    got = store.get("n1")
    assert got.last_install["ok"] is True
    assert "Dependencies installed" in got.last_install["message"]


def test_choose_connect_host_prefers_private_last_ok():
    from app.core.ssh_servers import choose_connect_host

    server = SshServer(
        id="n1",
        host="ec2-44-212-73-124.compute-1.amazonaws.com",
        last_ok_ip="172.31.89.224",
    )
    host, candidates = choose_connect_host(server)
    assert host == "172.31.89.224"
    assert "172.31.89.224" in candidates


def test_private_ip_helper():
    from app.core.ssh_servers import _is_private_ip

    assert _is_private_ip("172.31.67.5") is True
    assert _is_private_ip("44.212.73.124") is False


def test_public_ip_from_ec2_hostname():
    from app.core.ssh_servers import public_ip_from_ec2_hostname

    assert public_ip_from_ec2_hostname("ec2-44-212-73-124.compute-1.amazonaws.com") == "44.212.73.124"
    assert public_ip_from_ec2_hostname("ec2-44-212-73-124.us-east-1.compute.amazonaws.com") == "44.212.73.124"
    assert public_ip_from_ec2_hostname("example.com") == ""


def test_choose_connect_host_includes_decoded_public_ip():
    from app.core.ssh_servers import choose_connect_host

    server = SshServer(id="n2", host="ec2-10-0-0-5.compute-1.amazonaws.com")
    _host, candidates = choose_connect_host(server)
    assert "10.0.0.5" in candidates


def test_friendly_ssh_error_mentions_same_vpc():
    from app.core.ssh_servers import friendly_ssh_error

    msg = friendly_ssh_error("ssh timeout").lower()
    assert "same vpc" in msg
    assert "connect ip" not in msg
