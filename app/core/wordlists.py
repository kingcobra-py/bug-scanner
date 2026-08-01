"""Wordlist loading, normalization, and merge modes."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, Literal

from app.utils.normalize import normalize_path

PathsMode = Literal["merge", "custom_only", "builtin_only"]

ROOT = Path(__file__).resolve().parents[2]
WORDLIST_DIR = ROOT / "wordlists"


def load_wordlist(path: Path | str) -> list[str]:
    p = Path(path)
    if not p.exists():
        return []
    out: list[str] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        item = normalize_path(line)
        if item:
            out.append(item)
    return dedupe_paths(out)


def dedupe_paths(paths: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for p in paths:
        n = normalize_path(p)
        if not n or n in seen:
            continue
        seen.add(n)
        out.append(n)
    return out


def builtin_paths(kinds: Iterable[str] | None = None) -> list[str]:
    mapping = {
        "git": WORDLIST_DIR / "git.txt",
        "js": WORDLIST_DIR / "js_paths.txt",
        "config": WORDLIST_DIR / "config_env.txt",
        "common": WORDLIST_DIR / "common_sensitive.txt",
    }
    selected = list(kinds) if kinds else list(mapping.keys())
    paths: list[str] = []
    for kind in selected:
        if kind in mapping:
            paths.extend(load_wordlist(mapping[kind]))
    return dedupe_paths(paths)


def merge_paths(
    custom: Iterable[str] | None = None,
    mode: PathsMode = "merge",
    builtin_kinds: Iterable[str] | None = None,
) -> list[str]:
    custom_list = dedupe_paths(custom or [])
    if mode == "custom_only":
        return custom_list
    built = builtin_paths(builtin_kinds)
    if mode == "builtin_only":
        return built
    return dedupe_paths([*built, *custom_list])


def save_uploaded_wordlist(content: str | bytes, dest: Path) -> list[str]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        text = content.decode("utf-8", errors="ignore")
    else:
        text = content
    paths = []
    for line in text.splitlines():
        n = normalize_path(line)
        if n:
            paths.append(n)
    paths = dedupe_paths(paths)
    dest.write_text("\n".join(paths) + ("\n" if paths else ""), encoding="utf-8")
    return paths