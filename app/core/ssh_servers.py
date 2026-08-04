"""SSH server registry, metrics collection, and dependency install helpers."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import uuid
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


@dataclass
class SshServer:
    id: str
    host: str
    port: int = 22
    username: str = "ubuntu"
    auth_type: str = "key"  # key | password
    private_key: str = ""
    password: str = ""
    label: str = ""
    status: str = "unknown"  # online | offline | unknown
    last_error: str = ""
    last_install: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def display_host(self) -> str:
        return self.label or self.host

    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


_SSH_SERVER_FIELDS = {f.name for f in fields(SshServer)}


def _server_from_row(row: dict[str, Any]) -> SshServer:
    return SshServer(**{key: value for key, value in row.items() if key in _SSH_SERVER_FIELDS})


def friendly_ssh_error(message: str) -> str:
    """Rewrite common OpenSSH failures into operator-facing text."""
    text = (message or "").strip()
    low = text.lower()
    if "could not resolve hostname" in low or "name or service not known" in low or "temporary failure in name resolution" in low:
        return (
            "Could not resolve hostname — check the host spelling, or use the "
            "server's private/public IP. Controller DNS may also be temporarily overloaded."
        )
    if "connection timed out" in low or text == "ssh timeout" or "timed out" in low:
        return (
            "SSH timed out — host may be stopped, security group may block port 22 "
            "from this controller, or the network path is too slow."
        )
    if "permission denied" in low:
        return "SSH auth failed — check username / key / password."
    if "connection refused" in low:
        return "SSH connection refused — is sshd running on port 22?"
    return text


class SshServerStore:
    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.is_file():
            self._write([])

    def _read(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _write(self, rows: list[dict[str, Any]]) -> None:
        self.path.write_text(json.dumps(rows, indent=2), encoding="utf-8")

    def list(self) -> list[SshServer]:
        return [_server_from_row(row) for row in self._read()]

    def get(self, server_id: str) -> Optional[SshServer]:
        for row in self._read():
            if row.get("id") == server_id:
                return _server_from_row(row)
        return None

    def upsert(self, server: SshServer) -> SshServer:
        rows = self._read()
        now = datetime.now(timezone.utc).isoformat()
        if not server.created_at:
            server.created_at = now
        server.updated_at = now
        payload = asdict(server)
        replaced = False
        for idx, row in enumerate(rows):
            if row.get("id") == server.id:
                rows[idx] = payload
                replaced = True
                break
        if not replaced:
            rows.append(payload)
        self._write(rows)
        return server

    def delete(self, server_id: str) -> bool:
        rows = self._read()
        next_rows = [row for row in rows if row.get("id") != server_id]
        if len(next_rows) == len(rows):
            return False
        self._write(next_rows)
        return True


def _write_keyfile(private_key: str) -> str:
    key = (private_key or "").strip() + "\n"
    tmp = tempfile.NamedTemporaryFile("w", delete=False, prefix="bb-ssh-", suffix=".pem")
    tmp.write(key)
    tmp.flush()
    tmp.close()
    Path(tmp.name).chmod(0o600)
    return tmp.name


def _write_askpass() -> str:
    """Tiny helper so OpenSSH can read a password non-interactively."""
    tmp = tempfile.NamedTemporaryFile("w", delete=False, prefix="bb-ssh-askpass-", suffix=".sh")
    tmp.write("#!/bin/sh\nprintf '%s\\n' \"$BB_SSH_PASS\"\n")
    tmp.flush()
    tmp.close()
    Path(tmp.name).chmod(0o700)
    return tmp.name


def ssh_run(
    server: SshServer,
    remote_command: str = "",
    *,
    script: str = "",
    timeout: float = 20.0,
) -> tuple[int, str, str]:
    """Run a remote command over OpenSSH. Returns (rc, stdout, stderr).

    Prefer ``script=`` for multi-line bash; it is fed to ``bash -s`` on stdin
    so quoting/newlines stay intact.

    Supports private-key auth (default) and password auth via ``SSH_ASKPASS``.
    """
    keyfile = None
    askpass = None
    try:
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=12",
            "-o", "ServerAliveInterval=5",
            "-o", "ConnectionAttempts=2",
            "-p", str(int(server.port or 22)),
        ]
        env = os.environ.copy()
        use_password = (server.auth_type or "").lower() == "password" and bool(server.password)
        if use_password:
            askpass = _write_askpass()
            env["BB_SSH_PASS"] = server.password
            env["SSH_ASKPASS"] = askpass
            env["SSH_ASKPASS_REQUIRE"] = "force"
            # SSH_ASKPASS requires DISPLAY to be set even for headless use.
            env.setdefault("DISPLAY", ":0")
            cmd.extend([
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=1",
                "-o", "KbdInteractiveAuthentication=yes",
            ])
        else:
            cmd.extend(["-o", "BatchMode=yes"])
            if server.private_key.strip():
                keyfile = _write_keyfile(server.private_key)
                cmd.extend(["-i", keyfile])
            elif not server.private_key.strip() and (server.auth_type or "key") == "key":
                return 1, "", "private key is required for key auth"
        cmd.append(f"{server.username}@{server.host}")
        if script:
            cmd.append("bash -s")
        else:
            cmd.append(remote_command or "true")
        proc = subprocess.run(
            cmd,
            input=script or None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
            start_new_session=True,
        )
        stderr = friendly_ssh_error(proc.stderr or "") if proc.returncode else (proc.stderr or "")
        return proc.returncode, proc.stdout or "", stderr
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", friendly_ssh_error(exc.stderr or "ssh timeout")
    except Exception as exc:
        return 1, "", friendly_ssh_error(str(exc))
    finally:
        for path in (keyfile, askpass):
            if path:
                try:
                    Path(path).unlink(missing_ok=True)
                except Exception:
                    pass


_METRIC_SCRIPT = r"""
python3 - <<'PY'
import json, os, shutil, time
cores = os.cpu_count() or 0
load1 = load5 = load15 = 0.0
try:
    load1, load5, load15 = os.getloadavg()
except Exception:
    pass
mem_total = mem_used = mem_pct = 0.0
try:
    info = {}
    with open('/proc/meminfo') as fh:
        for line in fh:
            key, val = line.split(':', 1)
            info[key] = float(val.strip().split()[0]) * 1024
    mem_total = info.get('MemTotal', 0)
    mem_avail = info.get('MemAvailable', info.get('MemFree', 0))
    mem_used = max(mem_total - mem_avail, 0)
    mem_pct = (mem_used / mem_total * 100.0) if mem_total else 0.0
except Exception:
    pass
disk = shutil.disk_usage('/')
disk_pct = (disk.used / disk.total * 100.0) if disk.total else 0.0
# CPU: short sample via /proc/stat
def cpu_times():
    with open('/proc/stat') as fh:
        parts = fh.readline().split()
    nums = list(map(float, parts[1:]))
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    total = sum(nums)
    return idle, total
try:
    i1, t1 = cpu_times(); time.sleep(0.15); i2, t2 = cpu_times()
    cpu_pct = max(0.0, min(100.0, (1 - (i2 - i1) / max(t2 - t1, 1e-6)) * 100.0))
except Exception:
    cpu_pct = 0.0
procs = len([n for n in os.listdir('/proc') if n.isdigit()])
net_rx = net_tx = 0
try:
    with open('/proc/net/dev') as fh:
        for line in fh:
            if ':' not in line or line.strip().startswith('Inter') or 'lo:' in line:
                continue
            parts = line.split(':', 1)[1].split()
            net_rx += int(parts[0]); net_tx += int(parts[8])
except Exception:
    pass
def fmt_bytes(n):
    n = float(n or 0)
    gb = n / (1024 ** 3)
    if gb >= 100:
        return f'{gb:.0f}G'
    if gb >= 10:
        return f'{gb:.1f}G'
    if gb >= 1:
        return f'{gb:.2f}G'
    mb = n / (1024 ** 2)
    if mb >= 1:
        return f'{mb:.0f}M'
    kb = n / 1024
    return f'{kb:.0f}K'
print(json.dumps({
    'cpu_percent': round(cpu_pct, 1),
    'memory_percent': round(mem_pct, 1),
    'disk_percent': round(disk_pct, 1),
    'cores': cores,
    'load': f'{load1:.2f}',
    'load_1': load1, 'load_5': load5, 'load_15': load15,
    'procs': procs,
    'net': f'{fmt_bytes(net_rx)}/{fmt_bytes(net_tx)}',
    'net_rx': int(net_rx), 'net_tx': int(net_tx),
    'memory_used': int(mem_used), 'memory_total': int(mem_total),
    'disk_used': disk.used, 'disk_total': disk.total,
}))
PY
""".strip()


def collect_metrics(server: SshServer) -> dict[str, Any]:
    rc, out, err = ssh_run(server, script=_METRIC_SCRIPT, timeout=25)
    if rc != 0:
        return {
            "online": False,
            "error": friendly_ssh_error(err or out or f"ssh exit {rc}")[:300],
            "cpu_percent": 0,
            "memory_percent": 0,
            "disk_percent": 0,
            "cores": "-",
            "load": "-",
            "procs": "-",
            "net": "-",
        }
    try:
        data = json.loads(out.strip().splitlines()[-1])
        data["online"] = True
        data["error"] = ""
        return data
    except Exception:
        return {
            "online": False,
            "error": "bad metrics payload",
            "cpu_percent": 0,
            "memory_percent": 0,
            "disk_percent": 0,
            "cores": "-",
            "load": "-",
            "procs": "-",
            "net": "-",
        }


_INSTALL_SCRIPT = r"""
set -euo pipefail
APP=/opt/bb-scanner
sudo mkdir -p "$APP"
if [ ! -d "$APP/.git" ] && [ ! -f "$APP/main.py" ]; then
  sudo mkdir -p "$APP"
fi
# Ensure python + venv tooling
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y >/tmp/bb-deps.log 2>&1 || true
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip git >/tmp/bb-deps.log 2>&1 || true
fi
if [ -f "$APP/requirements.txt" ]; then
  if [ ! -x "$APP/.venv/bin/python" ]; then
    sudo python3 -m venv "$APP/.venv"
  fi
  sudo "$APP/.venv/bin/pip" install -q -U pip
  sudo "$APP/.venv/bin/pip" install -q -r "$APP/requirements.txt"
fi
# Runtime dirs
sudo mkdir -p "$APP/output/scans" "$APP/output/uploads"
sudo chmod -R a+rwX "$APP/output" || true
echo OK
""".strip()


def install_deps(server: SshServer) -> dict[str, Any]:
    rc, out, err = ssh_run(server, script=_INSTALL_SCRIPT, timeout=300)
    ok = rc == 0 and "OK" in (out or "")
    message = (
        "Dependencies installed on remote host (/opt/bb-scanner venv + packages)."
        if ok
        else friendly_ssh_error(err or out or "install failed")[:400]
    )
    return {
        "ok": ok,
        "exit_code": rc,
        "stdout": (out or "")[-4000:],
        "stderr": (err or "")[-2000:],
        "message": message,
        "at": datetime.now(timezone.utc).isoformat(),
    }


def preflight_server(server: SshServer) -> dict[str, Any]:
    """Probe one host for job use: SSH login + echo + light metrics."""
    metrics = collect_metrics(server)
    online = bool(metrics.get("online"))
    rc, out, err = ssh_run(server, "echo BB_SSH_OK && hostname", timeout=20)
    echo_ok = rc == 0 and "BB_SSH_OK" in (out or "")
    hostname = ""
    if echo_ok:
        lines = [ln.strip() for ln in (out or "").splitlines() if ln.strip()]
        hostname = next((ln for ln in lines if ln != "BB_SSH_OK"), "")
    ok = online and echo_ok
    error = ""
    if not ok:
        error = friendly_ssh_error(err or metrics.get("error") or out or "ssh preflight failed")[:300]
    return {
        "id": server.id,
        "host": server.host,
        "endpoint": server.endpoint(),
        "label": server.label or server.host,
        "username": server.username,
        "auth_type": server.auth_type,
        "ok": ok,
        "online": online,
        "echo_ok": echo_ok,
        "hostname": hostname,
        "error": error,
        "metrics": {
            "cpu_percent": metrics.get("cpu_percent", 0),
            "memory_percent": metrics.get("memory_percent", 0),
            "disk_percent": metrics.get("disk_percent", 0),
            "cores": metrics.get("cores", "-"),
            "load": metrics.get("load", "-"),
        },
    }


def preflight_servers(store: SshServerStore, server_ids: list[str]) -> list[dict[str, Any]]:
    """Validate selected SSH servers before attaching them to a job."""
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for sid in server_ids:
        sid = (sid or "").strip()
        if not sid or sid in seen:
            continue
        seen.add(sid)
        server = store.get(sid)
        if not server:
            results.append({
                "id": sid,
                "host": "",
                "endpoint": "",
                "label": sid,
                "username": "",
                "auth_type": "",
                "ok": False,
                "online": False,
                "echo_ok": False,
                "hostname": "",
                "error": "server not found",
                "metrics": {},
            })
            continue
        results.append(preflight_server(server))
    return results


def public_server_dict(server: SshServer) -> dict[str, Any]:
    data = asdict(server)
    # Never send private key / password material back to the browser after create.
    if data.get("private_key"):
        data["private_key"] = "***"
    if data.get("password"):
        data["password"] = "***"
    data["has_key"] = bool(server.private_key.strip())
    data["has_password"] = bool(server.password)
    data["endpoint"] = server.endpoint()
    return data


def new_server_id() -> str:
    return uuid.uuid4().hex[:12]
