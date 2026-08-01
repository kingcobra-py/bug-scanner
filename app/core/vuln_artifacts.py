"""Persist vulnerable hits into debug-friendly artifact files."""

from __future__ import annotations

import csv
import json
import re
import shutil
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from app.utils.normalize import safe_filename

CATEGORY_RULES: list[tuple[str, tuple[str, ...]]] = [
    ("git", ("git",)),
    ("env", ("config",)),
    ("js", ("js",)),
    ("wordpress", ("wordpress", "wp")),
    ("joomla", ("joomla",)),
    ("react2shell", ("react", "react2shell")),
    ("methods", ("methods",)),
]

URL_HINTS: list[tuple[str, re.Pattern[str]]] = [
    ("env", re.compile(r"(?:^|/)\.env(?:\.|$)|wp-config|configuration\.php", re.I)),
    ("git", re.compile(r"/\.git(?:/|$)", re.I)),
    ("js", re.compile(r"\.(?:js|map)(?:\?|$)", re.I)),
    ("wordpress", re.compile(r"wp-|xmlrpc|wp-json", re.I)),
    ("joomla", re.compile(r"joomla|/administrator|com_jce|/api/index\.php", re.I)),
    ("react2shell", re.compile(r"/_next/|__NEXT_DATA__|package\.json", re.I)),
]


def host_from_finding(finding: dict[str, Any]) -> str:
    for key in ("target", "url"):
        value = finding.get(key) or ""
        if not value:
            continue
        try:
            parsed = urlparse(value if "://" in value else f"https://{value}")
            if parsed.netloc:
                return parsed.netloc.lower()
        except Exception:
            continue
    return "unknown-host"


def classify_finding(finding: dict[str, Any]) -> list[str]:
    module = (finding.get("module") or "").lower()
    tags = [str(t).lower() for t in (finding.get("tags") or [])]
    title = (finding.get("title") or "").lower()
    url = (finding.get("url") or "").lower()
    ftype = (finding.get("type") or "").lower()
    blob = " ".join([module, " ".join(tags), title, url, ftype])

    cats: list[str] = []
    for category, markers in CATEGORY_RULES:
        if module in markers or any(m in tags for m in markers) or any(m in blob for m in markers):
            cats.append(category)
    for category, pattern in URL_HINTS:
        if pattern.search(url) or pattern.search(title):
            if category not in cats:
                cats.append(category)
    if ftype == "env" and "env" not in cats:
        cats.append("env")
    if not cats:
        cats.append("other")
    return cats


def detection_method(finding: dict[str, Any], categories: list[str]) -> str:
    module = finding.get("module") or "unknown"
    if module == "methods":
        evidence = finding.get("evidence") or ""
        interesting = re.search(r"interesting=\[([^\]]*)\]", evidence)
        if interesting and interesting.group(1).strip():
            return f"methods:{interesting.group(1)}"
        return "methods:http"
    if "wp2shell" in (finding.get("tags") or []) or "wp2shell" in (finding.get("title") or "").lower():
        return "wp2shell"
    if "react2shell" in categories or "cve-2025-55182" in str(finding.get("tags") or []).lower():
        return "react2shell"
    if "joomla" in categories and (
        "cve-2026-48907" in str(finding.get("tags") or []).lower() or "jce" in str(finding.get("tags") or []).lower()
    ):
        return "joomla_rce_surface"
    if "env" in categories:
        return "env"
    if "git" in categories:
        return "git"
    if "js" in categories:
        return "js"
    return module


def is_vuln_worthy(finding: dict[str, Any]) -> bool:
    severity = (finding.get("severity") or "info").lower()
    module = (finding.get("module") or "").lower()
    ftype = (finding.get("type") or "").lower()
    tags = [str(t).lower() for t in (finding.get("tags") or [])]
    if severity in {"critical", "high", "medium"}:
        return True
    if module in {"git", "config", "js", "wordpress", "joomla", "react", "methods"}:
        if ftype in {"env", "js_secret", "vuln", "path"}:
            return True
        if any(t in tags for t in ("detection-only", "priority-secrets", "wp2shell", "react2shell", "cve-2026-48907", "cve-2025-55182")):
            return True
        if severity == "low" and module in {"git", "config", "wordpress", "joomla", "react"}:
            return True
    return False


def write_vuln_artifacts(out_dir: Path | str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    root = Path(out_dir)
    vulns_dir = root / "vulns"
    if vulns_dir.exists():
        # Rewrite cleanly each pass so API refresh does not duplicate JSONL rows.
        for path in vulns_dir.rglob("*"):
            if path.is_file():
                try:
                    path.unlink()
                except Exception:
                    pass
    vulns_dir.mkdir(parents=True, exist_ok=True)

    by_target: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_method: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    index_rows: list[dict[str, Any]] = []

    for finding in findings:
        if not is_vuln_worthy(finding):
            continue
        categories = classify_finding(finding)
        host = host_from_finding(finding)
        method = detection_method(finding, categories)
        record = {
            "host": host,
            "target": finding.get("target"),
            "url": finding.get("url"),
            "method": method,
            "module": finding.get("module"),
            "categories": categories,
            "severity": finding.get("severity"),
            "type": finding.get("type"),
            "title": finding.get("title"),
            "confidence": finding.get("confidence"),
            "validated": finding.get("validated"),
            "tags": finding.get("tags") or [],
            "evidence": finding.get("evidence"),
            "raw_ref": finding.get("raw_ref"),
            "extracted": finding.get("extracted") or {},
            "id": finding.get("id"),
        }
        index_rows.append(record)
        by_target[host].append(record)
        by_method[method].append(record)

        for category in categories:
            by_category[category].append(record)
            cat_dir = vulns_dir / category
            cat_dir.mkdir(parents=True, exist_ok=True)
            fname = safe_filename(f"{host}__{finding.get('title') or finding.get('id') or 'hit'}") + ".json"
            (cat_dir / fname).write_text(json.dumps(record, indent=2), encoding="utf-8")
            with (cat_dir / "index.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
            # Keep full HTTP debug artifacts nearby when evidence exists.
            raw_ref = finding.get("raw_ref") or ""
            if raw_ref:
                try:
                    _copy_debug_artifact(Path(raw_ref), cat_dir, host)
                except Exception:
                    pass

    hosts = sorted(by_target.keys())
    summary = {
        "vulnerable_host_count": len(hosts),
        "vuln_finding_count": len(index_rows),
        "hosts": hosts,
        "by_category_counts": {k: len(v) for k, v in sorted(by_category.items())},
        "by_method_counts": {k: len(v) for k, v in sorted(by_method.items())},
    }

    (vulns_dir / "index.jsonl").write_text(
        "\n".join(json.dumps(row) for row in index_rows) + ("\n" if index_rows else ""),
        encoding="utf-8",
    )
    (vulns_dir / "by_target.json").write_text(json.dumps(by_target, indent=2), encoding="utf-8")
    (vulns_dir / "by_method.json").write_text(json.dumps(by_method, indent=2), encoding="utf-8")
    (vulns_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (vulns_dir / "hosts.txt").write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")

    with (vulns_dir / "by_target.csv").open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["host", "method", "module", "severity", "title", "url", "categories", "confidence"],
        )
        writer.writeheader()
        for host in hosts:
            for row in by_target[host]:
                writer.writerow(
                    {
                        "host": host,
                        "method": row.get("method"),
                        "module": row.get("module"),
                        "severity": row.get("severity"),
                        "title": row.get("title"),
                        "url": row.get("url"),
                        "categories": ",".join(row.get("categories") or []),
                        "confidence": row.get("confidence"),
                    }
                )

    md_lines = [
        "# Vulnerable Hosts",
        "",
        f"- Hosts: {len(hosts)}",
        f"- Findings: {len(index_rows)}",
        "",
    ]
    for host in hosts:
        md_lines.append(f"## `{host}`")
        for row in by_target[host]:
            md_lines.append(
                f"- **{row.get('method')}** · {row.get('severity')} · {row.get('title')} · `{row.get('url')}`"
            )
        md_lines.append("")
    (vulns_dir / "by_target.md").write_text("\n".join(md_lines), encoding="utf-8")

    return {
        "dir": str(vulns_dir),
        "summary": summary,
        "by_target": by_target,
        "by_method": by_method,
        "vulnerable_hosts": [
            {
                "host": host,
                "methods": sorted({row.get("method") for row in rows if row.get("method")}),
                "modules": sorted({row.get("module") for row in rows if row.get("module")}),
                "severities": sorted({row.get("severity") for row in rows if row.get("severity")}),
                "finding_count": len(rows),
                "findings": rows,
            }
            for host, rows in sorted(by_target.items())
        ],
    }


def _copy_debug_artifact(src: Path, cat_dir: Path, host: str) -> None:
    """Copy a .http/.txt body or a methods bundle into the vulns category folder."""
    if not src.exists():
        return
    # Method bundles: SUMMARY.txt plus per-method *.http files.
    if src.is_file() and src.name == "SUMMARY.txt" and any(src.parent.glob("*.http")):
        dest_dir = cat_dir / safe_filename(f"{host}__methods__{src.parent.name}")
        if not dest_dir.exists():
            shutil.copytree(src.parent, dest_dir)
        return
    if src.is_dir() and any(src.glob("*.http")):
        dest_dir = cat_dir / safe_filename(f"{host}__methods__{src.name}")
        if not dest_dir.exists():
            shutil.copytree(src, dest_dir)
        return
    if not src.is_file():
        return
    dest = cat_dir / (safe_filename(f"{host}__body__{src.stem}") + src.suffix)
    if not dest.exists():
        dest.write_bytes(src.read_bytes())
    # Also copy companion .txt/.bin/.http siblings written by save_http_response.
    for sibling in src.parent.glob(src.stem + ".*"):
        if sibling == src:
            continue
        sib_dest = cat_dir / (safe_filename(f"{host}__body__{sibling.stem}") + sibling.suffix)
        if not sib_dest.exists():
            sib_dest.write_bytes(sibling.read_bytes())
