"""Persistent, safe server-side target and path-list uploads."""

from __future__ import annotations

import hashlib
import re
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
MAX_UPLOAD_BYTES = 25 * 1024 * 1024


def safe_upload_name(filename: str) -> str:
    name = Path(filename or "upload.txt").name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return (name or "upload.txt")[:180]


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
        raise ValueError("uploaded file exceeds the 25 MB limit")

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
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
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


def delete_upload_file(record: dict[str, Any], upload_dir: Path) -> None:
    path = Path(record.get("stored_path") or "").resolve()
    root = upload_dir.resolve()
    if path.parent == root:
        path.unlink(missing_ok=True)
