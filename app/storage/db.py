"""SQLite persistence for scans, findings, and logs."""

from __future__ import annotations

import json
import queue
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
    delete,
    func,
    or_,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    __tablename__ = "scans"
    id = Column(String(32), primary_key=True)
    status = Column(String(32), default="pending")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    config_json = Column(Text, default="{}")
    progress_json = Column(Text, default="{}")
    summary_json = Column(Text, default="{}")
    output_dir = Column(String(512), default="")
    archived = Column(Integer, default=0)


class FindingRow(Base):
    __tablename__ = "findings"
    id = Column(String(64), primary_key=True)
    scan_id = Column(String(32), index=True)
    type = Column(String(64))
    severity = Column(String(16))
    target = Column(String(512))
    url = Column(String(1024))
    title = Column(String(512))
    evidence = Column(Text, default="")
    raw_ref = Column(String(1024), default="")
    extracted_json = Column(Text, default="{}")
    confidence = Column(Float, default=0.0)
    module = Column(String(64), default="")
    timestamp = Column(String(64), default="")
    validated = Column(Integer, default=0)
    tags_json = Column(Text, default="[]")


class LogRow(Base):
    __tablename__ = "logs"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String(32), index=True)
    timestamp = Column(String(64))
    level = Column(String(16))
    module = Column(String(64))
    message = Column(Text)


class UploadRow(Base):
    __tablename__ = "uploads"
    id = Column(String(32), primary_key=True)
    kind = Column(String(16), index=True)
    original_name = Column(String(255))
    stored_path = Column(String(1024), unique=True)
    item_count = Column(Integer, default=0)
    size_bytes = Column(Integer, default=0)
    sha256 = Column(String(64), default="")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ScanStore:
    def __init__(self, db_path: Path | str = "output/scans/scanner.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False: scan worker threads and the API share this engine.
        # timeout + WAL keep progress writers from stalling create-job / list APIs.
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            future=True,
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        Base.metadata.create_all(self.engine)
        # create_all does not add columns to an existing SQLite table.
        with self.engine.begin() as conn:
            columns = {row[1] for row in conn.exec_driver_sql("PRAGMA table_info(scans)")}
            if "archived" not in columns:
                conn.exec_driver_sql("ALTER TABLE scans ADD COLUMN archived INTEGER DEFAULT 0")
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self._lock = threading.Lock()
        # A scan can log thousands of lines/sec across hundreds of worker
        # threads. Committing each one synchronously under a shared lock was
        # the dominant bottleneck at high thread counts (every request stalls
        # behind every other thread's disk commit). Logs are now buffered in
        # memory and flushed in small batches by one background thread, so
        # add_log() never blocks a scan worker on disk I/O.
        self._log_queue: queue.Queue[tuple[str, dict[str, Any]] | None] = queue.Queue()
        self._log_flush_interval = 0.25
        self._log_flush_batch = 500
        self._log_counter_lock = threading.Lock()
        self._log_enqueued = 0
        self._log_committed = 0
        self._log_writer = threading.Thread(target=self._log_writer_loop, daemon=True)
        self._log_writer.start()

    def _log_writer_loop(self) -> None:
        while True:
            try:
                item = self._log_queue.get(timeout=self._log_flush_interval)
            except queue.Empty:
                continue
            if item is None:
                return
            batch = [item]
            while len(batch) < self._log_flush_batch:
                try:
                    nxt = self._log_queue.get_nowait()
                except queue.Empty:
                    break
                if nxt is None:
                    self._flush_log_batch(batch)
                    return
                batch.append(nxt)
            self._flush_log_batch(batch)

    def _flush_log_batch(self, batch: list[tuple[str, dict[str, Any]]]) -> None:
        if not batch:
            return
        try:
            with Session(self.engine) as s:
                for scan_id, event in batch:
                    s.add(
                        LogRow(
                            scan_id=scan_id,
                            timestamp=event.get("timestamp", ""),
                            level=event.get("level", "INFO"),
                            module=event.get("module", "engine"),
                            message=event.get("message", ""),
                        )
                    )
                s.commit()
        except Exception:
            pass
        finally:
            with self._log_counter_lock:
                self._log_committed += len(batch)

    def flush_logs(self, timeout: float = 5.0) -> None:
        """Block until every log queued so far has been committed. Used by tests/shutdown."""
        import time

        with self._log_counter_lock:
            target = self._log_enqueued
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._log_counter_lock:
                if self._log_committed >= target:
                    return
            time.sleep(0.01)

    def create_scan(self, scan_id: str, config: dict[str, Any], output_dir: str) -> None:
        with self._lock, Session(self.engine) as s:
            existing = s.get(ScanRow, scan_id)
            if existing:
                # Resume / restart of the same id must keep findings + progress.
                # Engine re-create_scan() uses ScanConfig fields only — preserve
                # dashboard metadata (SSH fleet assignment, etc.) already stored.
                try:
                    old = json.loads(existing.config_json or "{}")
                except Exception:
                    old = {}
                if isinstance(old, dict):
                    preserved = {
                        key: value
                        for key, value in old.items()
                        if key not in config and key not in {"targets", "custom_paths"}
                    }
                    config = {**preserved, **config}
                existing.config_json = json.dumps(config)
                existing.output_dir = output_dir or existing.output_dir
                existing.status = existing.status or "pending"
                existing.archived = 0
                existing.updated_at = datetime.now(timezone.utc)
            else:
                s.add(
                    ScanRow(
                        id=scan_id,
                        status="pending",
                        config_json=json.dumps(config),
                        output_dir=output_dir,
                    )
                )
            s.commit()

    def rebuild_scan_config(self, scan_id: str) -> Optional[dict[str, Any]]:
        """Rebuild a ScanConfig-ready dict from a stopped scan's artifacts."""
        row = self.get_scan(scan_id, compact=False)
        if not row:
            return None
        config = dict(row.get("config") or {})
        out_dir = Path(row.get("output_dir") or "")
        if not out_dir:
            return None
        targets_file = out_dir / "targets.txt"
        paths_file = out_dir / "custom_paths.txt"
        config["scan_id"] = scan_id
        config["targets"] = []
        config["custom_paths"] = []
        config["output_dir"] = str(out_dir.parent) if out_dir.name == scan_id else str(out_dir)
        # engine uses output_dir / scan_id — store output_dir is usually the scan folder.
        # Prefer parent as ScanConfig.output_dir when folder is already .../scans/<id>.
        if out_dir.name == scan_id:
            config["output_dir"] = str(out_dir.parent)
        else:
            config["output_dir"] = str(out_dir)
        if targets_file.is_file():
            config["targets_path"] = str(targets_file)
        if paths_file.is_file():
            config["wordlist_path"] = str(paths_file)
        config.setdefault("target_count", int(config.get("target_count") or 0))
        return config

    def update_status(self, scan_id: str, status: str) -> None:
        with self._lock, Session(self.engine) as s:
            row = s.get(ScanRow, scan_id)
            if not row:
                return
            row.status = status
            row.updated_at = datetime.now(timezone.utc)
            s.commit()

    def update_progress(self, scan_id: str, progress: dict[str, Any]) -> None:
        with self._lock, Session(self.engine) as s:
            row = s.get(ScanRow, scan_id)
            if not row:
                return
            row.progress_json = json.dumps(progress)
            row.updated_at = datetime.now(timezone.utc)
            s.commit()

    def update_summary(self, scan_id: str, summary: dict[str, Any]) -> None:
        with self._lock, Session(self.engine) as s:
            row = s.get(ScanRow, scan_id)
            if not row:
                return
            row.summary_json = json.dumps(summary)
            row.updated_at = datetime.now(timezone.utc)
            s.commit()

    def add_finding(self, scan_id: str, finding: dict[str, Any]) -> None:
        with self._lock, Session(self.engine) as s:
            row = FindingRow(
                id=finding["id"],
                scan_id=scan_id,
                type=finding.get("type", "other"),
                severity=finding.get("severity", "info"),
                target=finding.get("target", ""),
                url=finding.get("url", ""),
                title=finding.get("title", ""),
                evidence=finding.get("evidence", ""),
                raw_ref=finding.get("raw_ref", ""),
                extracted_json=json.dumps(finding.get("extracted", {})),
                confidence=float(finding.get("confidence", 0)),
                module=finding.get("module", ""),
                timestamp=finding.get("timestamp", ""),
                validated=1 if finding.get("validated") else 0,
                tags_json=json.dumps(finding.get("tags", [])),
            )
            s.merge(row)
            s.commit()

    def add_log(self, scan_id: str, event: dict[str, Any]) -> None:
        # Non-blocking: the background writer batches these to avoid
        # serializing every scan worker thread behind one SQLite commit.
        with self._log_counter_lock:
            self._log_enqueued += 1
        self._log_queue.put((scan_id, event))

    def add_upload(self, upload: dict[str, Any]) -> None:
        with self._lock, Session(self.engine) as s:
            s.merge(
                UploadRow(
                    id=upload["id"],
                    kind=upload["kind"],
                    original_name=upload["original_name"],
                    stored_path=upload["stored_path"],
                    item_count=int(upload.get("item_count", 0)),
                    size_bytes=int(upload.get("size_bytes", 0)),
                    sha256=upload.get("sha256", ""),
                )
            )
            s.commit()

    def list_uploads(self, kind: Optional[str] = None) -> list[dict[str, Any]]:
        with Session(self.engine) as s:
            stmt = select(UploadRow).order_by(UploadRow.created_at.desc())
            if kind:
                stmt = stmt.where(UploadRow.kind == kind)
            return [self._upload_dict(row) for row in s.scalars(stmt).all()]

    def get_upload(self, upload_id: str) -> Optional[dict[str, Any]]:
        with Session(self.engine) as s:
            row = s.get(UploadRow, upload_id)
            return self._upload_dict(row) if row else None

    def delete_upload(self, upload_id: str) -> Optional[dict[str, Any]]:
        with self._lock, Session(self.engine) as s:
            row = s.get(UploadRow, upload_id)
            if not row:
                return None
            result = self._upload_dict(row)
            s.delete(row)
            s.commit()
            return result

    def list_scans(
        self,
        limit: int = 100,
        compact: bool = False,
        include_archived: bool = False,
    ) -> list[dict[str, Any]]:
        with Session(self.engine) as s:
            stmt = select(ScanRow).order_by(ScanRow.created_at.desc())
            if not include_archived:
                stmt = stmt.where(ScanRow.archived == 0)
            rows = s.scalars(stmt.limit(max(1, min(limit, 1000)))).all()
            return [self._scan_dict(r, compact=compact) for r in rows]

    def get_scan(self, scan_id: str, compact: bool = False) -> Optional[dict[str, Any]]:
        with Session(self.engine) as s:
            row = s.get(ScanRow, scan_id)
            return self._scan_dict(row, compact=compact) if row else None

    def delete_scan(self, scan_id: str) -> bool:
        # Log writes are queued asynchronously (see add_log); flush first so
        # a write already in flight when this is called can't land after
        # the delete and leave an orphaned row behind.
        self.flush_logs(timeout=2.0)
        with self._lock, Session(self.engine) as s:
            row = s.get(ScanRow, scan_id)
            if not row:
                return False
            s.execute(delete(FindingRow).where(FindingRow.scan_id == scan_id))
            s.execute(delete(LogRow).where(LogRow.scan_id == scan_id))
            s.delete(row)
            s.commit()
            return True

    def archive_scan(self, scan_id: str) -> bool:
        with self._lock, Session(self.engine) as s:
            row = s.get(ScanRow, scan_id)
            if not row:
                return False
            row.archived = 1
            row.updated_at = datetime.now(timezone.utc)
            s.commit()
            return True

    def slim_stored_summaries(self) -> int:
        """Rewrite fat legacy summaries that embed full target arrays."""
        changed = 0
        with self._lock, Session(self.engine) as s:
            rows = s.scalars(select(ScanRow)).all()
            for row in rows:
                summary = json.loads(row.summary_json or "{}")
                if "targets" not in summary and "custom_paths" not in summary:
                    # Still drop oversized progress blobs copied into summary.
                    if "progress" not in summary and len(row.summary_json or "") < 4096:
                        continue
                slim = self._slim_summary(summary)
                # Keep a compact progress snapshot if present.
                progress = summary.get("progress")
                if isinstance(progress, dict):
                    slim["progress"] = {
                        key: progress.get(key)
                        for key in (
                            "total", "done", "failed", "queued", "hits", "vulnerable_hosts",
                            "secrets", "requests", "rps", "percent", "eta_seconds",
                        )
                        if key in progress
                    }
                new_json = json.dumps(slim)
                if new_json != (row.summary_json or "{}"):
                    row.summary_json = new_json
                    changed += 1
            if changed:
                s.commit()
        return changed

    def query_findings(
        self,
        scan_id: str,
        severity: Optional[str] = None,
        ftype: Optional[str] = None,
        module: Optional[str] = None,
        q: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        """Return ``(page_items, total_matching)`` with SQL filters + LIMIT.

        Used by the Results dashboard so a scan with hundreds of thousands of
        findings does not force the API (or browser) to materialize every row
        just to show one page of 10/20/50/100.
        """
        filters = [FindingRow.scan_id == scan_id]
        if severity:
            filters.append(FindingRow.severity == severity)
        if ftype:
            filters.append(FindingRow.type == ftype)
        if module:
            filters.append(FindingRow.module == module)
        if q:
            like = f"%{q.strip()}%"
            filters.append(
                or_(
                    FindingRow.title.like(like),
                    FindingRow.url.like(like),
                    FindingRow.target.like(like),
                    FindingRow.evidence.like(like),
                    FindingRow.module.like(like),
                )
            )
        with Session(self.engine) as s:
            total = int(s.scalar(select(func.count()).select_from(FindingRow).where(*filters)) or 0)
            stmt = (
                select(FindingRow)
                .where(*filters)
                .order_by(FindingRow.timestamp.desc(), FindingRow.id.desc())
                .offset(max(0, int(offset or 0)))
            )
            if limit is not None:
                stmt = stmt.limit(max(0, int(limit)))
            rows = s.scalars(stmt).all()
            return [self._finding_dict(r) for r in rows], total

    def get_findings(
        self,
        scan_id: str,
        severity: Optional[str] = None,
        ftype: Optional[str] = None,
        module: Optional[str] = None,
        q: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        items, _total = self.query_findings(
            scan_id,
            severity=severity,
            ftype=ftype,
            module=module,
            q=q,
            limit=limit,
            offset=offset,
        )
        return items

    def finding_stats(self, scan_id: str) -> dict[str, Any]:
        """Cheap SQL aggregates for Results summary cards (no row materialization)."""
        with Session(self.engine) as s:
            total = int(
                s.scalar(
                    select(func.count()).select_from(FindingRow).where(FindingRow.scan_id == scan_id)
                )
                or 0
            )
            by_severity: dict[str, int] = {
                str(sev or "info"): int(count)
                for sev, count in s.execute(
                    select(FindingRow.severity, func.count())
                    .where(FindingRow.scan_id == scan_id)
                    .group_by(FindingRow.severity)
                ).all()
            }
            by_module: dict[str, int] = {
                str(mod or "unknown"): int(count)
                for mod, count in s.execute(
                    select(FindingRow.module, func.count())
                    .where(FindingRow.scan_id == scan_id)
                    .group_by(FindingRow.module)
                ).all()
            }
        return {"finding_count": total, "by_severity": by_severity, "by_module": by_module}

    def get_secret_candidate_findings(self, scan_id: str) -> list[dict[str, Any]]:
        """Load only findings that may contain extractable secrets/SMTP.

        Large scans store millions of empty ``{"secrets": []}`` blobs. Pulling
        every row into Python for Results made the tab take 1–2 minutes; JSON
        filters keep this to the few thousand rows that actually matter.
        """
        sql = (
            "SELECT id FROM findings WHERE scan_id = ? AND ("
            "json_array_length(json_extract(extracted_json, '$.secrets')) > 0 "
            "OR json_array_length(json_extract(extracted_json, '$.smtp')) > 0 "
            "OR type = 'secrets'"
            ")"
        )
        try:
            with self.engine.connect() as conn:
                ids = [row[0] for row in conn.exec_driver_sql(sql, (scan_id,)).fetchall()]
        except Exception:
            # Older SQLite without JSON1 — fall back to a bounded Python filter.
            return self._secret_candidates_python_fallback(scan_id)

        if not ids:
            return []
        with Session(self.engine) as s:
            rows = s.scalars(select(FindingRow).where(FindingRow.id.in_(ids))).all()
            return [self._finding_dict(r) for r in rows]

    def _secret_candidates_python_fallback(self, scan_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        with Session(self.engine) as s:
            rows = s.scalars(select(FindingRow).where(FindingRow.scan_id == scan_id)).all()
            for row in rows:
                if (row.type or "") == "secrets":
                    out.append(self._finding_dict(row))
                    continue
                raw = row.extracted_json or ""
                if len(raw) <= 2:
                    continue
                try:
                    extracted = json.loads(raw)
                except Exception:
                    continue
                if (extracted.get("secrets") or extracted.get("smtp")):
                    out.append(self._finding_dict(row))
        return out

    def get_vuln_candidate_findings(self, scan_id: str) -> list[dict[str, Any]]:
        """Findings that can contribute to the vulnerable-hosts panel.

        Skips pure info/path noise that dominates huge scans when on-disk
        ``vulns/`` indexes are unavailable.
        """
        modules = ("git", "config", "js", "wordpress", "joomla", "react", "methods")
        severities = ("critical", "high", "medium")
        with Session(self.engine) as s:
            rows = s.scalars(
                select(FindingRow).where(
                    FindingRow.scan_id == scan_id,
                    or_(
                        FindingRow.severity.in_(severities),
                        FindingRow.module.in_(modules),
                    ),
                )
            ).all()
            return [self._finding_dict(r) for r in rows]

    def get_finding(self, scan_id: str, finding_id: str) -> Optional[dict[str, Any]]:
        with Session(self.engine) as s:
            row = s.get(FindingRow, finding_id)
            if not row or row.scan_id != scan_id:
                return None
            return self._finding_dict(row)

    def get_logs(self, scan_id: str, level: Optional[str] = None, module: Optional[str] = None, limit: int = 500) -> list[dict[str, Any]]:
        with Session(self.engine) as s:
            rows = s.scalars(
                select(LogRow).where(LogRow.scan_id == scan_id).order_by(LogRow.id.desc()).limit(limit)
            ).all()
            out = []
            for r in reversed(rows):
                if level and r.level != level.upper():
                    continue
                if module and r.module != module:
                    continue
                out.append(
                    {
                        "timestamp": r.timestamp,
                        "level": r.level,
                        "module": r.module,
                        "message": r.message,
                    }
                )
            return out

    @staticmethod
    def _slim_summary(summary: dict[str, Any]) -> dict[str, Any]:
        """Drop bulky fields (full target lists) from dashboard payloads."""
        slim = {
            "scan_id": summary.get("scan_id"),
            "generated_at": summary.get("generated_at"),
            "finding_count": summary.get("finding_count"),
            "vuln_finding_count": summary.get("vuln_finding_count"),
            "by_severity": summary.get("by_severity") or {},
            "modules": summary.get("modules") or [],
        }
        if "target_count" in summary:
            slim["target_count"] = summary.get("target_count")
        elif isinstance(summary.get("targets"), list):
            slim["target_count"] = len(summary.get("targets") or [])
        return {key: value for key, value in slim.items() if value not in (None, [], {})}

    @staticmethod
    def _scan_dict(row: ScanRow, compact: bool = False) -> dict[str, Any]:
        config = json.loads(row.config_json or "{}")
        summary = json.loads(row.summary_json or "{}")
        if compact:
            targets = config.pop("targets", None)
            custom_paths = config.pop("custom_paths", None)
            if targets is not None or "target_count" not in config:
                config["target_count"] = len(targets or [])
            if custom_paths is not None or "custom_path_count" not in config:
                config["custom_path_count"] = len(custom_paths or [])
            # Older scans stored the full target list inside summary_json (~175KB).
            # That alone made Jobs polling ~1MB and caused browser "Failed to fetch".
            summary = ScanStore._slim_summary(summary)
        return {
            "id": row.id,
            "status": row.status,
            "created_at": row.created_at.isoformat() if row.created_at else "",
            "updated_at": row.updated_at.isoformat() if row.updated_at else "",
            "config": config,
            "progress": json.loads(row.progress_json or "{}"),
            "summary": summary,
            "output_dir": row.output_dir,
            "archived": bool(row.archived),
        }

    @staticmethod
    def _finding_dict(row: FindingRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "type": row.type,
            "severity": row.severity,
            "target": row.target,
            "url": row.url,
            "title": row.title,
            "evidence": row.evidence,
            "raw_ref": row.raw_ref,
            "extracted": json.loads(row.extracted_json or "{}"),
            "confidence": row.confidence,
            "module": row.module,
            "timestamp": row.timestamp,
            "validated": bool(row.validated),
            "tags": json.loads(row.tags_json or "[]"),
        }

    @staticmethod
    def _upload_dict(row: UploadRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "kind": row.kind,
            "original_name": row.original_name,
            "stored_path": row.stored_path,
            "item_count": row.item_count,
            "size_bytes": row.size_bytes,
            "sha256": row.sha256,
            "created_at": row.created_at.isoformat() if row.created_at else "",
        }