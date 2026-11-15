"""Resumable, part-based upload manager (S0).

Flow: ``init(filename, size, sha256?)`` -> ``put_part(id, n, bytes, sha256?)`` (any order,
retries allowed) -> ``complete(id)`` which assembles ``upload/original.<ext>`` inside a new
scan directory, verifies hashes, and writes the first ledger entries.

Nothing here parses the uploaded content. The original file name is kept only as
metadata; bytes are stored under a generated name. Part numbers are 0-based.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import shutil
import threading
import unicodedata
from datetime import datetime
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

import poisonlens
from poisonlens.audit.ledger import EntryType, Ledger
from poisonlens.core.config import UploadLimits
from poisonlens.core.errors import IntegrityError, PathSafetyError, UnsafeFileError, UploadStateError
from poisonlens.core.paths import ScanPaths, default_data_dir
from poisonlens.core.schemas import utc_now
from poisonlens.ingest.limits import check_disk_quota, check_upload_size
from poisonlens.ingest.names import BIDI_CONTROLS

UPLOAD_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_EXT_PART_RE = re.compile(r"^[a-z0-9]{1,10}$")
_COMPOUND_EXTS = ("tar.gz", "tar.bz2", "tar.xz")
_CHUNK = 1024 * 1024


class UploadState(str, Enum):
    OPEN = "open"
    COMPLETED = "completed"


class PartInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    size: int
    sha256: str


class UploadSession(BaseModel):
    model_config = ConfigDict(extra="forbid")

    upload_id: str
    original_name: str
    stored_ext: str
    size: int
    expected_sha256: str | None = None
    part_size: int
    n_parts: int
    created_at: datetime = Field(default_factory=utc_now)
    state: UploadState = UploadState.OPEN
    parts: dict[int, PartInfo] = Field(default_factory=dict)

    def expected_part_size(self, n: int) -> int:
        if n < self.n_parts - 1:
            return self.part_size
        return self.size - self.part_size * (self.n_parts - 1)

    def missing_parts(self) -> list[int]:
        return [n for n in range(self.n_parts) if n not in self.parts]


class CompletedUpload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    original_name: str
    stored_path: str  # relative to the scan root
    size: int
    sha256: str


def validate_upload_filename(name: str, limits: UploadLimits) -> str:
    """Reject names that could confuse paths, logs or UIs. Returns the NFC-normalized name."""
    if not isinstance(name, str) or not name.strip():
        raise UnsafeFileError("file name is empty", check_id="F04")
    if "\x00" in name:
        raise UnsafeFileError("file name contains a NUL byte", check_id="F04")
    if any(ch in BIDI_CONTROLS for ch in name):
        raise UnsafeFileError("file name contains bidirectional control characters", check_id="F04")
    if any(unicodedata.category(ch) in ("Cc", "Cf") for ch in name):
        raise UnsafeFileError("file name contains control characters", check_id="F04")
    if "/" in name or "\\" in name:
        raise UnsafeFileError("file name contains a path separator", check_id="F04")
    if name in (".", ".."):
        raise UnsafeFileError("file name is a path component", check_id="F04")
    if len(name.encode("utf-8")) > limits.max_filename_length:
        raise UnsafeFileError("file name is too long", check_id="F04")
    return unicodedata.normalize("NFC", name)


def stored_extension(name: str) -> str:
    """Lower-case extension used for the stored file (``csv``, ``tar.gz``...); ``bin`` if none/unsafe."""
    lower = name.lower()
    for comp in _COMPOUND_EXTS:
        if lower.endswith("." + comp):
            return comp
    if lower.endswith(".tgz"):
        return "tgz"
    stem, dot, ext = lower.rpartition(".")
    if dot and stem and _EXT_PART_RE.match(ext):
        return ext
    return "bin"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + f".{secrets.token_hex(4)}.tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def tool_versions() -> dict[str, str]:
    import platform
    import sys

    return {"poisonlens": poisonlens.__version__, "python": sys.version.split()[0], "platform": platform.platform()}


class UploadManager:
    """Manages upload sessions under ``<data_dir>/uploads/<upload_id>/``."""

    def __init__(self, limits: UploadLimits, data_dir: Path | None = None):
        self.limits = limits
        self.data_dir = Path(data_dir) if data_dir is not None else default_data_dir()
        self.uploads_root = (self.data_dir / "uploads").resolve()
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    # ---------------------------------------------------------------- internals

    def _lock(self, upload_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._locks.setdefault(upload_id, threading.Lock())

    def _dir(self, upload_id: str) -> Path:
        if not isinstance(upload_id, str) or not UPLOAD_ID_RE.fullmatch(upload_id):
            raise PathSafetyError("invalid upload id")
        return self.uploads_root / upload_id

    def _load(self, upload_id: str) -> UploadSession:
        meta = self._dir(upload_id) / "meta.json"
        if not meta.exists():
            raise UploadStateError(f"unknown upload {upload_id}")
        return UploadSession.model_validate_json(meta.read_text(encoding="utf-8"))

    def _save(self, session: UploadSession) -> None:
        _atomic_write(self._dir(session.upload_id) / "meta.json", session.model_dump_json(indent=2).encode())

    # ---------------------------------------------------------------- API

    def init(self, filename: str, size: int, sha256: str | None = None) -> UploadSession:
        """Start an upload. Validates name, size, optional final hash and disk quota."""
        name = validate_upload_filename(filename, self.limits)
        check_upload_size(size, self.limits)
        if sha256 is not None:
            sha256 = sha256.lower()
            if not _SHA_RE.match(sha256):
                raise IntegrityError("sha256 must be 64 hex characters")
        check_disk_quota(self.data_dir, size, self.limits)
        upload_id = secrets.token_hex(16)
        session = UploadSession(
            upload_id=upload_id,
            original_name=name,
            stored_ext=stored_extension(name),
            size=size,
            expected_sha256=sha256,
            part_size=self.limits.part_size_bytes,
            n_parts=max(1, math.ceil(size / self.limits.part_size_bytes)),
        )
        (self._dir(upload_id) / "parts").mkdir(parents=True, exist_ok=False)
        self._save(session)
        return session

    def status(self, upload_id: str) -> UploadSession:
        return self._load(upload_id)

    def put_part(self, upload_id: str, n: int, data: bytes, sha256: str | None = None) -> PartInfo:
        """Store part ``n``. Re-sending identical bytes is a no-op; different bytes are rejected."""
        with self._lock(upload_id):
            session = self._load(upload_id)
            if session.state is not UploadState.OPEN:
                raise UploadStateError("upload is already completed")
            if not isinstance(n, int) or not 0 <= n < session.n_parts:
                raise UploadStateError(f"part number must be in 0..{session.n_parts - 1}")
            expected = session.expected_part_size(n)
            if len(data) != expected:
                raise IntegrityError(f"part {n}: expected {expected} bytes, got {len(data)}")
            digest = hashlib.sha256(data).hexdigest()
            if sha256 is not None and sha256.lower() != digest:
                raise IntegrityError(f"part {n}: sha256 mismatch")
            if n in session.parts:
                if session.parts[n].sha256 == digest:
                    return session.parts[n]
                raise IntegrityError(f"part {n} was already uploaded with different content")
            _atomic_write(self._dir(upload_id) / "parts" / f"{n:06d}.part", data)
            info = PartInfo(size=len(data), sha256=digest)
            session.parts[n] = info
            self._save(session)
            return info

    def abort(self, upload_id: str) -> None:
        with self._lock(upload_id):
            shutil.rmtree(self._dir(upload_id), ignore_errors=True)

    def complete(self, upload_id: str) -> CompletedUpload:
        """Assemble parts into a new scan's ``upload/`` dir, verify, and open the ledger."""
        with self._lock(upload_id):
            session = self._load(upload_id)
            if session.state is not UploadState.OPEN:
                raise UploadStateError("upload is already completed")
            missing = session.missing_parts()
            if missing:
                raise UploadStateError(f"missing parts: {missing[:20]}{'...' if len(missing) > 20 else ''}")

            scan_id = "scan_" + secrets.token_hex(8)
            paths = ScanPaths(scan_id, data_dir=self.data_dir).ensure()
            stored_rel = f"upload/original.{session.stored_ext}"
            target = paths.resolve(stored_rel)
            parts_dir = self._dir(upload_id) / "parts"
            total = hashlib.sha256()
            written = 0
            try:
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
                with os.fdopen(fd, "wb") as out:
                    for n in range(session.n_parts):
                        part_hash = hashlib.sha256()
                        with open(parts_dir / f"{n:06d}.part", "rb") as fh:
                            for block in iter(lambda: fh.read(_CHUNK), b""):
                                part_hash.update(block)
                                total.update(block)
                                out.write(block)
                                written += len(block)
                        if part_hash.hexdigest() != session.parts[n].sha256:
                            raise IntegrityError(f"part {n} changed on disk after upload")
                    out.flush()
                    os.fsync(out.fileno())
                digest = total.hexdigest()
                if written != session.size:
                    raise IntegrityError(f"assembled {written} bytes, expected {session.size}")
                if session.expected_sha256 is not None and digest != session.expected_sha256:
                    raise IntegrityError("final sha256 does not match the value declared at init")
            except BaseException:
                shutil.rmtree(paths.root, ignore_errors=True)
                shutil.rmtree(self._dir(upload_id), ignore_errors=True)
                raise

            result = CompletedUpload(
                scan_id=scan_id,
                original_name=session.original_name,
                stored_path=stored_rel,
                size=session.size,
                sha256=digest,
            )
            (paths.upload / "meta.json").write_text(
                json.dumps(result.model_dump(), indent=2, ensure_ascii=False), encoding="utf-8"
            )
            ledger = Ledger(paths.audit / "ledger.jsonl")
            ledger.append(
                EntryType.SCAN_STARTED,
                {"scan_id": scan_id, "dataset_sha256": digest, "size": session.size, "tool_versions": tool_versions()},
            )
            ledger.append(
                EntryType.FILE_ACCEPTED,
                {"original_name": session.original_name, "stored_path": stored_rel, "sha256": digest},
            )
            shutil.rmtree(self._dir(upload_id), ignore_errors=True)
            return result
