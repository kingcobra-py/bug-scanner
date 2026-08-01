"""SQLite persistence for scans, findings, and logs."""

from __future__ import annotations

import json
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
        self.engine = create_engine(f"sqlite:///{self.db_path}", future=True)
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        self._lock = threading.Lock()

    def create_scan(self, scan_id: str, config: dict[str, Any], output_dir: str) -> None:
        with self._lock, Session(self.engine) as s:
            row = ScanRow(
                id=scan_id,
                status="pending",
                config_json=json.dumps(config),
                output_dir=output_dir,
            )
            s.merge(row)
            s.commit()

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
        with self._lock, Session(self.engine) as s:
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

    def list_scans(self) -> list[dict[str, Any]]:
        with Session(self.engine) as s:
            rows = s.scalars(select(ScanRow).order_by(ScanRow.created_at.desc())).all()
            return [self._scan_dict(r) for r in rows]

    def get_scan(self, scan_id: str) -> Optional[dict[str, Any]]:
        with Session(self.engine) as s:
            row = s.get(ScanRow, scan_id)
            return self._scan_dict(row) if row else None

    def get_findings(
        self,
        scan_id: str,
        severity: Optional[str] = None,
        ftype: Optional[str] = None,
        module: Optional[str] = None,
        q: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        with Session(self.engine) as s:
            rows = s.scalars(
                select(FindingRow).where(FindingRow.scan_id == scan_id)
            ).all()
            out = []
            for r in rows:
                if severity and r.severity != severity:
                    continue
                if ftype and r.type != ftype:
                    continue
                if module and r.module != module:
                    continue
                item = self._finding_dict(r)
                if q:
                    blob = json.dumps(item).lower()
                    if q.lower() not in blob:
                        continue
                out.append(item)
            return out

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
    def _scan_dict(row: ScanRow) -> dict[str, Any]:
        return {
            "id": row.id,
            "status": row.status,
            "created_at": row.created_at.isoformat() if row.created_at else "",
            "updated_at": row.updated_at.isoformat() if row.updated_at else "",
            "config": json.loads(row.config_json or "{}"),
            "progress": json.loads(row.progress_json or "{}"),
            "summary": json.loads(row.summary_json or "{}"),
            "output_dir": row.output_dir,
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