"""SSH server registry, metrics collection, and dependency install helpers."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
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
    metrics: dict[str, Any] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""

    def display_host(self) -> str:
        return self.label or self.host

    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"


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
        return [SshServer(**row) for row in self._read()]

    def get(self, server_id: str) -> Optional[SshServer]:
        for row in self._read():
            if row.get("id") == server_id:
                return SshServer(**row)
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
            "-o", "ConnectTimeout=8",
            "-o", "ServerAliveInterval=5",
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
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        return 124, exc.stdout or "", exc.stderr or "ssh timeout"
    except Exception as exc:
        return 1, "", str(exc)
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
print(json.dumps({
    'cpu_percent': round(cpu_pct, 1),
    'memory_percent': round(mem_pct, 1),
    'disk_percent': round(disk_pct, 1),
    'cores': cores,
    'load': f'{load1:.2f}',
    'load_1': load1, 'load_5': load5, 'load_15': load15,
    'procs': procs,
    'net': f'{net_rx // 1024}k/{net_tx // 1024}k',
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
            "error": (err or out or f"ssh exit {rc}").strip()[:300],
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
    ok = rc == 0 and "OK" in out
    return {
        "ok": ok,
        "exit_code": rc,
        "stdout": out[-4000:],
        "stderr": err[-2000:],
        "message": "Dependencies installed" if ok else (err or out or "install failed")[:400],
    }


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
