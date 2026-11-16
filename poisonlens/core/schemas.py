"""Shared data contracts (pydantic v2) for every stage, the API and the UI.

All models forbid unknown fields so a typo in a persisted artifact is an error,
not silently dropped data. Everything round-trips through JSON.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from poisonlens.core.config import ScanConfig

SHA256_PATTERN = r"^[0-9a-f]{64}$"
CHECK_ID_PATTERN = r"^[A-Z][0-9]{2}$"


def utc_now() -> datetime:
    """Timezone-aware current UTC time (all timestamps in PoisonLens are UTC)."""
    return datetime.now(timezone.utc)


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- enums


class Modality(str, Enum):
    TABULAR = "tabular"
    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    MIXED = "mixed"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """0 = most severe. Use for sorting findings."""
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


class Tier(int, Enum):
    """Soft-quarantine tier. ``Tier.weight`` is the spec's training weight for the tier."""

    KEEP = 1
    DOWNWEIGHT = 2
    QUARANTINE = 3

    @property
    def weight(self) -> float:
        return _TIER_WEIGHTS[self]


_TIER_WEIGHTS: dict[Tier, float] = {Tier.KEEP: 1.0, Tier.DOWNWEIGHT: 0.20, Tier.QUARANTINE: 0.0}


class StageName(str, Enum):
    """Stage ids S0-S7 in pipeline order (spec section 1)."""

    INGEST = "ingest"
    INSPECT = "inspect"
    SECURITY = "security"
    QUALITY = "quality"
    PROBE = "probe"
    DETECT = "detect"
    SANITIZE = "sanitize"
    SEAL = "seal"


STAGE_ORDER: list[StageName] = list(StageName)


class StageStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScanStatus(str, Enum):
    CREATED = "created"  # upload finished, profile not yet confirmed
    CONFIGURED = "configured"  # user confirmed label/profile
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    HALTED = "halted"  # stopped early by a critical file finding; still sealed with a report
    FAILED = "failed"
    CANCELLED = "cancelled"


class Verdict(str, Enum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    LIKELY_POISONED = "likely_poisoned"
    UNSAFE_FILE = "unsafe_file"


# --------------------------------------------------------------------------- findings


class Location(_Model):
    """Where a finding applies. Every field is optional; set the ones that make sense."""

    file: str | None = None  # sanitized member path inside the upload / archive
    sheet: str | None = None
    table: str | None = None
    row: int | None = Field(default=None, ge=0)
    column: str | None = None
    record_id: str | None = None
    byte_offset: int | None = Field(default=None, ge=0)


class Finding(_Model):
    """One result of a security or quality check (spec section 3)."""

    id: str = Field(min_length=1, max_length=128)
    check_id: str = Field(pattern=CHECK_ID_PATTERN)
    severity: Severity
    title: str = Field(min_length=1, max_length=300)
    detail: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)  # never raw PII/secrets: masked samples only
    location: Location | None = None
    owasp_refs: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    remediation: str = ""

    @field_validator("cwe")
    @classmethod
    def _cwe_format(cls, v: list[str]) -> list[str]:
        for item in v:
            if not (item.startswith("CWE-") and item[4:].isdigit()):
                raise ValueError(f"CWE reference must look like 'CWE-123', got {item!r}")
        return v


# --------------------------------------------------------------------------- profile


class ColumnProfile(_Model):
    name: str
    dtype: str
    null_rate: float = Field(ge=0.0, le=1.0)
    cardinality: int = Field(ge=0)
    mean_length: float | None = Field(default=None, ge=0.0)  # strings only


class LabelCandidate(_Model):
    column: str
    score: float = Field(ge=0.0, le=1.0)
    reason: str


class SplitInfo(_Model):
    column: str
    counts: dict[str, int]


class Capabilities(_Model):
    """What can run for this dataset. ``reasons`` explains every disabled capability."""

    labels: bool
    security: bool = True
    quality: bool = True
    probe: bool
    detect: bool
    reasons: dict[str, str] = Field(default_factory=dict)


class ContainerInfo(_Model):
    """Something the user can pick inside a file: a sheet, table, array, record element or member file."""

    name: str
    kind: str  # "sheet" | "table" | "view" | "array" | "element" | "file" | "key"
    n_records: int | None = Field(default=None, ge=0)
    shape: list[int] | None = None  # arrays
    dtype: str | None = None  # arrays
    state: str | None = None  # sheets: "visible" | "hidden" | "veryHidden"
    selectable: bool = True  # False when the container cannot be loaded (e.g. object arrays, virtual tables)
    note: str = ""


class Selection(_Model):
    """User choices that steer loading. ``None`` means "use the adapter's default"."""

    member: str | None = None  # archive uploads: which extracted data file to read
    container: str | None = None  # table / array (X) / JSON key / XML record element
    sheets: list[str] | None = None  # spreadsheets: one or more sheets with a common header
    label_column: str | None = None  # tabular/text label column, or the y array for arrays
    text_column: str | None = None
    y_array: str | None = None


class DatasetProfile(_Model):
    format: str
    modality: Modality
    n_records: int = Field(ge=0)
    columns: list[ColumnProfile] = Field(default_factory=list)
    label_candidates: list[LabelCandidate] = Field(default_factory=list)
    label_chosen: str | None = None
    splits: SplitInfo | None = None
    class_hist: dict[str, int] = Field(default_factory=dict)
    capabilities: Capabilities
    # Additions beyond the build plan's field list (see docs/MIGRATION_NOTES.md, Phase 3):
    adapter: str = ""
    containers: list[ContainerInfo] = Field(default_factory=list)
    selection: Selection = Field(default_factory=Selection)  # defaults the UI pre-selects
    text_column: str | None = None
    sampled: bool = False  # True when columns/class_hist come from a sample (inspect), not a full pass (load)
    warnings: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- scan state


class StageResult(_Model):
    stage: StageName
    status: StageStatus
    started_at: datetime | None = None
    ended_at: datetime | None = None
    artifacts: dict[str, str] = Field(default_factory=dict)  # artifact name -> sha256 hex
    warnings: list[str] = Field(default_factory=list)

    @field_validator("artifacts")
    @classmethod
    def _sha256_values(cls, v: dict[str, str]) -> dict[str, str]:
        pat = re.compile(SHA256_PATTERN)
        for name, digest in v.items():
            if not pat.match(digest):
                raise ValueError(f"artifact {name!r}: expected lowercase sha256 hex, got {digest!r}")
        return v


class ScanState(_Model):
    scan_id: str
    status: ScanStatus
    current_stage: StageName | None = None
    profile: DatasetProfile | None = None
    config: ScanConfig = Field(default_factory=ScanConfig)
    stage_results: dict[StageName, StageResult] = Field(default_factory=dict)
    verdict: Verdict | None = None
