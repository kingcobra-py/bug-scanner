"""Persistent, safe server-side target and path-list uploads."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import uuid
from pathlib import Path
from typing import Any, Literal

from app.core.wordlists import (
    load_wordlist,
    parse_target_lines,
    save_uploaded_targets,
    save_uploaded_wordlist,
)
from app.storage.db import ScanStore

UploadKind = Literal["targets", "wordlist"]
MAX_UPLOAD_BYTES = 5 * 1024 * 1024 * 1024
CHUNK_SIZE = 8 * 1024 * 1024
DIRECT_UPLOAD_BYTES = 32 * 1024 * 1024
_session_locks: dict[str, threading.Lock] = {}
_session_locks_guard = threading.Lock()


def safe_upload_name(filename: str) -> str:
    name = Path(filename or "upload.txt").name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return (name or "upload.txt")[:180]


def _session_lock(upload_id: str) -> threading.Lock:
    with _session_locks_guard:
        return _session_locks.setdefault(upload_id, threading.Lock())


def _session_path(upload_dir: Path, upload_id: str) -> Path:
    if not re.fullmatch(r"[a-f0-9]{16}", upload_id or ""):
        raise ValueError("invalid upload id")
    return upload_dir.resolve() / f".{upload_id}.upload.json"


def _part_path(upload_dir: Path, upload_id: str) -> Path:
    return upload_dir.resolve() / f".{upload_id}.upload.part"


def _read_session(upload_dir: Path, upload_id: str) -> dict[str, Any]:
    path = _session_path(upload_dir, upload_id)
    if not path.is_file():
        raise FileNotFoundError("upload session not found")
    return json.loads(path.read_text(encoding="utf-8"))


def _write_session(upload_dir: Path, upload_id: str, session: dict[str, Any]) -> None:
    path = _session_path(upload_dir, upload_id)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(session), encoding="utf-8")
    tmp.replace(path)


def init_chunk_upload(
    upload_dir: Path,
    *,
    kind: UploadKind,
    filename: str,
    total_size: int,
) -> dict[str, Any]:
    if kind not in {"targets", "wordlist"}:
        raise ValueError("upload kind must be targets or wordlist")
    if total_size <= 0:
        raise ValueError("uploaded file is empty")
    if total_size > MAX_UPLOAD_BYTES:
        raise ValueError("uploaded file exceeds the 5 GB limit")
    upload_dir.mkdir(parents=True, exist_ok=True)
    upload_id = uuid.uuid4().hex[:16]
    original_name = safe_upload_name(filename)
    total_chunks = math.ceil(total_size / CHUNK_SIZE)
    session = {
        "id": upload_id,
        "kind": kind,
        "original_name": original_name,
        "total_size": total_size,
        "chunk_size": CHUNK_SIZE,
        "total_chunks": total_chunks,
        "received_chunks": [],
    }
    # A sparse destination avoids holding chunks in RAM or doubling disk use.
    with _part_path(upload_dir, upload_id).open("wb") as fh:
        fh.truncate(total_size)
    _write_session(upload_dir, upload_id, session)
    return session


def write_upload_chunk(
    upload_dir: Path,
    upload_id: str,
    chunk_index: int,
    content: bytes,
) -> dict[str, Any]:
    lock = _session_lock(upload_id)
    with lock:
        session = _read_session(upload_dir, upload_id)
        total_chunks = int(session["total_chunks"])
        chunk_size = int(session["chunk_size"])
        total_size = int(session["total_size"])
        if chunk_index < 0 or chunk_index >= total_chunks:
            raise ValueError("invalid chunk index")
        expected = min(chunk_size, total_size - (chunk_index * chunk_size))
        if len(content) != expected:
            raise ValueError(f"chunk size mismatch: expected {expected}, received {len(content)}")
        part = _part_path(upload_dir, upload_id)
        if not part.is_file():
            raise FileNotFoundError("partial upload file not found")
        fd = os.open(part, os.O_WRONLY)
        try:
            os.pwrite(fd, content, chunk_index * chunk_size)
        finally:
            os.close(fd)
        received = {int(value) for value in session.get("received_chunks", [])}
        received.add(chunk_index)
        session["received_chunks"] = sorted(received)
        _write_session(upload_dir, upload_id, session)
        received_bytes = sum(
            min(chunk_size, total_size - (index * chunk_size))
            for index in received
        )
        return {
            "id": upload_id,
            "received_bytes": received_bytes,
            "total_size": total_size,
            "received_chunks": session["received_chunks"],
            "total_chunks": total_chunks,
        }


def get_chunk_upload_status(upload_dir: Path, upload_id: str) -> dict[str, Any]:
    with _session_lock(upload_id):
        session = _read_session(upload_dir, upload_id)
    chunk_size = int(session["chunk_size"])
    total_size = int(session["total_size"])
    received = [int(value) for value in session.get("received_chunks", [])]
    return {
        **session,
        "received_bytes": sum(
            min(chunk_size, total_size - (index * chunk_size))
            for index in received
        ),
    }


def _inspect_text_upload(path: Path, kind: UploadKind) -> tuple[int, list[str], str]:
    """Count usable lines and hash a large upload without loading it into RAM."""
    count = 0
    preview: list[str] = []
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for raw in fh:
            digest.update(raw)
            line = raw.decode("utf-8", errors="ignore").strip()
            if not line or line.startswith("#"):
                continue
            if " #" in line:
                line = line.split(" #", 1)[0].strip()
            if kind == "wordlist" and line and not line.startswith(("/", "http://", "https://")):
                line = "/" + line
            if not line:
                continue
            count += 1
            if len(preview) < 20:
                preview.append(line)
    return count, preview, digest.hexdigest()


def complete_chunk_upload(
    store: ScanStore,
    upload_dir: Path,
    upload_id: str,
) -> dict[str, Any]:
    lock = _session_lock(upload_id)
    with lock:
        session = _read_session(upload_dir, upload_id)
        expected = set(range(int(session["total_chunks"])))
        received = {int(value) for value in session.get("received_chunks", [])}
        missing = sorted(expected - received)
        if missing:
            raise ValueError(f"upload incomplete; {len(missing)} chunks missing")
        part = _part_path(upload_dir, upload_id)
        if not part.is_file() or part.stat().st_size != int(session["total_size"]):
            raise ValueError("partial upload size mismatch")
        kind: UploadKind = session["kind"]
        item_count, preview, sha256 = _inspect_text_upload(part, kind)
        if not item_count:
            raise ValueError(f"no valid {kind} entries found")
        final = (upload_dir.resolve() / f"{upload_id}_{session['original_name']}").resolve()
        if final.parent != upload_dir.resolve():
            raise ValueError("invalid upload filename")
        part.replace(final)
        record = {
            "id": upload_id,
            "kind": kind,
            "original_name": session["original_name"],
            "stored_path": str(final),
            "item_count": item_count,
            "size_bytes": final.stat().st_size,
            "sha256": sha256,
        }
        store.add_upload(record)
        _session_path(upload_dir, upload_id).unlink(missing_ok=True)
        with _session_locks_guard:
            _session_locks.pop(upload_id, None)
        return {**record, "preview": preview}


def create_upload(
    store: ScanStore,
    upload_dir: Path,
    *,
    kind: UploadKind,
    filename: str,
    content: bytes,
) -> dict[str, Any]:
    if kind not in {"targets", "wordlist"}:
        raise ValueError("upload kind must be targets or wordlist")
    if not content:
        raise ValueError("uploaded file is empty")
    if len(content) > MAX_UPLOAD_BYTES:
        raise ValueError("uploaded file exceeds the 5 GB limit")

    upload_id = uuid.uuid4().hex[:16]
    original_name = safe_upload_name(filename)
    stored_name = f"{upload_id}_{original_name}"
    path = (upload_dir / stored_name).resolve()
    root = upload_dir.resolve()
    if path.parent != root:
        raise ValueError("invalid upload filename")

    if kind == "targets":
        items = save_uploaded_targets(content, path)
    else:
        items = save_uploaded_wordlist(content, path)
    if not items:
        path.unlink(missing_ok=True)
        raise ValueError(f"no valid {kind} entries found")

    record = {
        "id": upload_id,
        "kind": kind,
        "original_name": original_name,
        "stored_path": str(path),
        "item_count": len(items),
        "size_bytes": path.stat().st_size,
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    store.add_upload(record)
    return {**record, "preview": items[:20]}


def read_upload_items(record: dict[str, Any]) -> list[str]:
    path = Path(record.get("stored_path") or "")
    if not path.is_file():
        raise FileNotFoundError("uploaded file no longer exists on the server")
    if record.get("kind") == "targets":
        return parse_target_lines(path.read_bytes())
    if record.get("kind") == "wordlist":
        return load_wordlist(path)
    raise ValueError("unknown upload kind")


def preview_upload_items(record: dict[str, Any], limit: int = 50) -> list[str]:
    """Read only the first useful lines; safe even for multi-gigabyte uploads."""
    path = Path(record.get("stored_path") or "")
    if not path.is_file():
        raise FileNotFoundError("uploaded file no longer exists on the server")
    kind = record.get("kind")
    preview: list[str] = []
    with path.open("rb") as fh:
        for raw in fh:
            line = raw.decode("utf-8", errors="ignore").strip()
            if not line or line.startswith("#"):
                continue
            if " #" in line:
                line = line.split(" #", 1)[0].strip()
            if kind == "wordlist" and line and not line.startswith(("/", "http://", "https://")):
                line = "/" + line
            if line:
                preview.append(line)
            if len(preview) >= limit:
                break
    return preview


def delete_upload_file(record: dict[str, Any], upload_dir: Path) -> None:
    path = Path(record.get("stored_path") or "").resolve()
    root = upload_dir.resolve()
    if path.parent == root:
        path.unlink(missing_ok=True)


def safe_download_path(record: dict[str, Any], upload_dir: Path) -> Path:
    path = Path(record.get("stored_path") or "").resolve()
    if path.parent != upload_dir.resolve() or not path.is_file():
        raise FileNotFoundError("uploaded file no longer exists on the server")
    return path
