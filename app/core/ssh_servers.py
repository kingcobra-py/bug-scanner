"""SSH server registry, metrics collection, and dependency install helpers."""

from __future__ import annotations

import ipaddress
import json
import os
import random
import socket
import struct
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
    # Optional IP used for the TCP/SSH connection (prefer VPC private IP).
    # Display/label can keep the public DNS name in ``host``.
    connect_ip: str = ""
    # Last IP that successfully completed an SSH probe.
    last_ok_ip: str = ""
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
            "Could not resolve hostname — controller DNS is flaky under load. "
            "Set Connect IP to the EC2 private IP (Network tab) and retry."
        )
    if "connection timed out" in low or text == "ssh timeout" or "timed out" in low:
        return (
            "SSH timed out from this controller on port 22. Public EC2 DNS often "
            "resolves to a public IP that this controller cannot reach. Set "
            "Connect IP to the instance private IP and allow TCP 22 from this controller."
        )
    if "permission denied" in low:
        return "SSH auth failed — check username / key / password."
    if "connection refused" in low:
        return "SSH connection refused — is sshd running on port 22?"
    return text


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except ValueError:
        return False


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address((value or "").strip()).is_private
    except ValueError:
        return False


def _dns_a_query(nameserver: str, name: str, timeout: float = 1.5) -> list[str]:
    """Tiny UDP DNS A lookup — avoids flaky systemd-resolved stub hangs."""
    host = (name or "").strip().rstrip(".")
    if not host or _is_ip(host):
        return [host] if host else []
    tid = random.randint(0, 65535)
    labels = b"".join(bytes([len(part)]) + part.encode("utf-8") for part in host.split(".")) + b"\x00"
    req = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + labels + struct.pack(">HH", 1, 1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(req, (nameserver, 53))
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    if len(data) < 12:
        return []
    ancount = struct.unpack(">H", data[6:8])[0]
    pos = 12
    # skip question
    while pos < len(data) and data[pos]:
        pos += data[pos] + 1
    pos += 5  # null + type + class
    ips: list[str] = []
    for _ in range(ancount):
        if pos >= len(data):
            break
        if data[pos] & 0xC0 == 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos]:
                pos += data[pos] + 1
            pos += 1
        if pos + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[pos : pos + 10])
        pos += 10
        rdata = data[pos : pos + rdlen]
        pos += rdlen
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(rdata))
    return ips


def resolve_ssh_targets(host: str) -> list[str]:
    """Resolve SSH host to candidate IPs (private addresses first)."""
    host = (host or "").strip()
    if not host:
        return []
    if _is_ip(host):
        return [host]
    ips: list[str] = []
    for ns in ("172.31.0.2", "127.0.0.53"):
        for _ in range(2):
            try:
                for ip in _dns_a_query(ns, host):
                    if ip not in ips:
                        ips.append(ip)
                if ips:
                    break
            except OSError:
                continue
        if ips:
            break
    if not ips:
        for _ in range(3):
            try:
                for fam, _t, _p, _c, sockaddr in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
                    if fam == socket.AF_INET:
                        ip = sockaddr[0]
                        if ip not in ips:
                            ips.append(ip)
                if ips:
                    break
            except OSError:
                continue
    # Prefer VPC/private addresses — public EIP is often unreachable from controller.
    ips.sort(key=lambda ip: (0 if _is_private_ip(ip) else 1, ip))
    return ips


def choose_connect_host(server: SshServer) -> tuple[str, list[str]]:
    """Return (connect_host, candidates) for SSH."""
    if (server.connect_ip or "").strip():
        ip = server.connect_ip.strip()
        return ip, [ip]
    candidates: list[str] = []
    if (server.last_ok_ip or "").strip():
        candidates.append(server.last_ok_ip.strip())
    for ip in resolve_ssh_targets(server.host):
        if ip not in candidates:
            candidates.append(ip)
    if not candidates:
        # Last resort: let OpenSSH try the raw hostname.
        return server.host, [server.host]
    # Private first already from resolve; keep last_ok_ip first if present.
    return candidates[0], candidates


def tcp_check(host: str, port: int, timeout: float = 4.0) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


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

    Connection target preference:
    1. ``connect_ip`` (explicit private IP)
    2. ``last_ok_ip``
    3. DNS candidates with private IPs first
    """
    keyfile = None
    askpass = None
    try:
        env = os.environ.copy()
        use_password = (server.auth_type or "").lower() == "password" and bool(server.password)
        auth_opts: list[str] = []
        if use_password:
            askpass = _write_askpass()
            env["BB_SSH_PASS"] = server.password
            env["SSH_ASKPASS"] = askpass
            env["SSH_ASKPASS_REQUIRE"] = "force"
            # SSH_ASKPASS requires DISPLAY to be set even for headless use.
            env.setdefault("DISPLAY", ":0")
            auth_opts = [
                "-o", "PreferredAuthentications=password,keyboard-interactive",
                "-o", "PubkeyAuthentication=no",
                "-o", "NumberOfPasswordPrompts=1",
                "-o", "KbdInteractiveAuthentication=yes",
            ]
        else:
            auth_opts = ["-o", "BatchMode=yes"]
            if server.private_key.strip():
                keyfile = _write_keyfile(server.private_key)
                auth_opts.extend(["-i", keyfile])
            elif not server.private_key.strip() and (server.auth_type or "key") == "key":
                return 1, "", "private key is required for key auth"

        _preferred, candidates = choose_connect_host(server)
        port = int(server.port or 22)
        # Drop candidates that fail a quick TCP probe when we have alternatives.
        reachable = [ip for ip in candidates if tcp_check(ip, port, timeout=3.0)]
        try_hosts = reachable or candidates
        last_rc, last_out, last_err = 1, "", "ssh failed"
        per_host_timeout = max(8.0, min(float(timeout), 20.0))
        for idx, target in enumerate(try_hosts):
            # Budget remaining wall time across candidates.
            remaining = float(timeout) - (idx * 3.0)
            if remaining < 6.0 and idx > 0:
                break
            cmd = [
                "ssh",
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=8",
                "-o", "ServerAliveInterval=5",
                "-o", "ConnectionAttempts=1",
                "-o", f"HostKeyAlias={server.host}",
                "-p", str(port),
                *auth_opts,
                f"{server.username}@{target}",
            ]
            if script:
                cmd.append("bash -s")
            else:
                cmd.append(remote_command or "true")
            try:
                proc = subprocess.run(
                    cmd,
                    input=script or None,
                    capture_output=True,
                    text=True,
                    timeout=min(per_host_timeout, remaining if remaining > 0 else per_host_timeout),
                    check=False,
                    env=env,
                    start_new_session=True,
                )
            except subprocess.TimeoutExpired as exc:
                last_rc, last_out, last_err = 124, exc.stdout or "", friendly_ssh_error(exc.stderr or "ssh timeout")
                continue
            last_rc = proc.returncode
            last_out = proc.stdout or ""
            last_err = friendly_ssh_error(proc.stderr or "") if proc.returncode else (proc.stderr or "")
            if proc.returncode == 0:
                # Remember working IP for later probes (survives DNS flapping).
                if _is_ip(target):
                    server.last_ok_ip = target
                    if not (server.connect_ip or "").strip() and _is_private_ip(target):
                        server.connect_ip = target
                return proc.returncode, last_out, last_err
        if last_rc != 0 and not (server.connect_ip or "").strip():
            resolved = ", ".join(candidates[:4]) or "none"
            hint = (
                f" Tried: {resolved}. Set Connect IP to the EC2 private IP from the "
                "AWS console Network tab."
            )
            if hint not in last_err:
                last_err = (last_err + hint).strip()
        return last_rc, last_out, last_err
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
