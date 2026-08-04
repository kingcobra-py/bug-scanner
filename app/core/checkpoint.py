"""Durable target-completion checkpoints for scan resume after reboot."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Iterable, Iterator


CHECKPOINT_NAME = "completed_indices.jsonl"
META_NAME = "checkpoint_meta.json"


def checkpoint_path(out_dir: Path | str) -> Path:
    return Path(out_dir) / CHECKPOINT_NAME


def meta_path(out_dir: Path | str) -> Path:
    return Path(out_dir) / META_NAME


def load_completed_indices(out_dir: Path | str) -> set[int]:
    path = checkpoint_path(out_dir)
    if not path.is_file():
        return set()
    done: set[int] = set()
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    # Prefer plain integer lines; also accept {"index": N}.
                    if line[0] == "{":
                        data = json.loads(line)
                        done.add(int(data["index"]))
                    else:
                        done.add(int(line))
                except Exception:
                    continue
    except OSError:
        return set()
    return done


def append_completed_index(out_dir: Path | str, index: int) -> None:
    """Append one completed absolute stream index (multiprocess-safe O_APPEND)."""
    path = checkpoint_path(out_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = f"{int(index)}\n".encode("utf-8")
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)


def write_meta(out_dir: Path | str, **fields: object) -> None:
    path = meta_path(out_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing: dict = {}
    if path.is_file():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            existing = {}
    existing.update(fields)
    path.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")


def read_meta(out_dir: Path | str) -> dict:
    path = meta_path(out_dir)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def count_completed(out_dir: Path | str) -> int:
    return len(load_completed_indices(out_dir))


def iter_indexed_targets(
    targets: Iterable[str],
    targets_path: str = "",
    *,
    skip: set[int] | None = None,
    normalize=None,
) -> Iterator[tuple[int, str]]:
    """Yield ``(absolute_index, normalized_url)``, skipping completed indices."""
    from app.core.wordlists import iter_target_lines
    from app.utils.normalize import normalize_target as _normalize

    norm = normalize or _normalize
    skip = skip or set()
    index = 0
    for target in targets:
        normalized = norm((target or "").strip())
        if not normalized:
            continue
        if index not in skip:
            yield index, normalized
        index += 1
    if targets_path:
        for target in iter_target_lines(targets_path):
            normalized = norm(target)
            if not normalized:
                continue
            if index not in skip:
                yield index, normalized
            index += 1


class CheckpointWriter:
    """Thread-safe batching wrapper around append_completed_index."""

    def __init__(self, out_dir: Path | str) -> None:
        self.out_dir = Path(out_dir)
        self._lock = threading.Lock()

    def mark(self, index: int) -> None:
        with self._lock:
            append_completed_index(self.out_dir, index)
