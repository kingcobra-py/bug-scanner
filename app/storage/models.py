"""Domain models for scans and findings."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import uuid

from app.utils.dedupe import finding_id


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    STOPPING = "stopping"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


@dataclass
class Finding:
    type: str
    severity: str
    target: str
    url: str
    title: str
    evidence: str = ""
    raw_ref: str = ""
    extracted: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    module: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    validated: bool = False
    tags: list[str] = field(default_factory=list)
    id: str = ""

    def __post_init__(self) -> None:
        if not self.id:
            value = ""
            if self.extracted:
                value = str(sorted(self.extracted.items()))
            self.id = finding_id(self.type, self.target, self.url, self.title, value)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TargetContext:
    url: str
    live: bool = False
    final_url: str = ""
    status_code: int = 0
    title: str = ""
    tech: list[str] = field(default_factory=list)
    soft404_profile: dict[str, Any] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProgressSnapshot:
    total: int = 0
    done: int = 0
    failed: int = 0
    queued: int = 0
    hits: int = 0
    secrets: int = 0
    timeouts: int = 0
    requests: int = 0
    rps: float = 0.0
    current_target: str = ""
    current_module: str = ""
    percent: float = 0.0
    eta_seconds: Optional[float] = None
    module_progress: dict[str, dict[str, int]] = field(default_factory=dict)


@dataclass
class ScanConfig:
    targets: list[str]
    threads: int = 20
    timeout: float = 8.0
    connect_timeout: float = 5.0
    retries: int = 2
    modules: list[str] = field(default_factory=lambda: [
        "git", "js", "config", "path", "methods", "wordpress", "joomla", "react", "crawl"
    ])
    paths_mode: str = "merge"
    custom_paths: list[str] = field(default_factory=list)
    output_dir: str = "output/scans"
    formats: list[str] = field(default_factory=lambda: ["json", "md", "csv"])
    verify_tls: bool = False
    proxy: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    scope_notes: str = ""
    redact_secrets: bool = True
    method_test_trace: bool = False
    probe_both_schemes: bool = True
    max_body_bytes: int = 2_097_152
    verbose: bool = False
    scan_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])


@dataclass
class ScanContext:
    config: ScanConfig
    output_dir: Any  # Path
    stop_event: Any  # threading.Event
    progress: Any  # ProgressManager
    store: Any  # ScanStore
    http: Any  # HttpClient
    logger: Any = None
    findings: list[Finding] = field(default_factory=list)
    bodies: list[tuple[str, str]] = field(default_factory=list)  # (url, body)