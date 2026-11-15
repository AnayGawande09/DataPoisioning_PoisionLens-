"""Streaming safe extractor for zip, tar(.gz/.bz2/.xz), single-file gz/bz2/xz and 7z.

Every archive is handled in two passes:

1. **Plan** — read only headers. Each member is classified (regular file, directory,
   symlink/hardlink/device/other) and its name is checked with
   :func:`poisonlens.ingest.names.analyze_member_path`. Unsafe paths and link/device
   members are F03 (critical); with ``halt_on_critical`` the whole upload is rejected
   before a single byte is written. Name hygiene problems are F04 (sanitized, or skipped
   for NUL / collisions). Declared sizes are checked against the limits (F02).
2. **Extract** — regular files are streamed in 64 KiB blocks to sanitized paths opened
   with ``O_EXCL`` (never overwriting, never following an existing link) and mode 0600.
   Entry count, per-member size, total size and compression ratio are enforced on the
   *actual* bytes produced, so lying headers cannot bypass the caps (F02).

Archives found inside archives are extracted in place (``<member>.extracted/``) up to
``max_nesting_depth`` levels, sharing one byte/entry budget. Any F02 breach or halting
F03 stops everything and removes what was written: a rejected upload leaves nothing behind.
"""

from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import lzma
import os
import shutil
import stat
import tarfile
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any

from pydantic import BaseModel, ConfigDict, Field

from poisonlens.core.config import ArchiveLimits
from poisonlens.core.errors import LimitExceededError, UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import Finding, Location
from poisonlens.ingest.limits import ArchiveBudget
from poisonlens.ingest.names import analyze_member_path, collision_key
from poisonlens.security.catalogue import make_finding

BLOCK = 64 * 1024
MAX_EXAMPLES = 20
_DECOMPRESSORS: dict[str, Any] = {"gzip": gzip.open, "bz2": bz2.open, "xz": lzma.open}


class ExtractedMember(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str  # posix path relative to the extraction root
    source: str  # where it came from, e.g. "upload!images/cat/1.png!inner.zip!x.png"
    size: int
    sha256: str
    depth: int


class SkippedMember(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str
    reason: str


class ExtractionReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    members: list[ExtractedMember] = Field(default_factory=list)
    skipped: list[SkippedMember] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    nested_archives: list[str] = Field(default_factory=list)
    halted: bool = False
    halt_reason: str | None = None
    entries_seen: int = 0
    total_bytes: int = 0


class _Halt(Exception):
    """Internal: abort the whole extraction (reason already recorded)."""


@dataclass
class _Planned:
    raw: str
    target: str  # sanitized relative path (including any nesting prefix)
    is_dir: bool
    declared_size: int
    compressed_size: int | None
    handle: Any  # ZipInfo / TarInfo name / 7z filename


class _CountingReader(io.RawIOBase):
    """Counts decompressed bytes read from a stream and enforces a hard ceiling."""

    def __init__(self, inner: IO[bytes], ceiling: int, budget: ArchiveBudget):
        self.inner = inner
        self.ceiling = ceiling
        self.budget = budget
        self.count = 0

    def readable(self) -> bool:
        return True

    def readinto(self, b: Any) -> int:
        data = self.inner.read(len(b))
        n = len(data)
        b[:n] = data
        self.count += n
        if self.count > self.ceiling:
            raise LimitExceededError(
                "decompressed stream exceeds the total size limit",
                limit="max_total_bytes",
                limit_value=self.budget.limits.max_total_bytes,
                observed=self.count,
            )
        lim = self.budget.limits
        if self.count >= lim.ratio_check_min_bytes and self.count / self.budget.container_bytes > (
            lim.max_compression_ratio
        ):
            raise LimitExceededError(
                "overall compression ratio exceeds the limit",
                limit="max_compression_ratio",
                limit_value=lim.max_compression_ratio,
                observed=round(self.count / self.budget.container_bytes, 1),
            )
        return n


class SafeExtractor:
    """Extract one uploaded archive (and its nested archives) into ``dest``."""

    def __init__(self, limits: ArchiveLimits, *, halt_on_critical: bool = True):
        self.limits = limits
        self.halt_on_critical = halt_on_critical
        self.report = ExtractionReport()
        self._issues: dict[tuple[str, str], list[str]] = {}
        self._file_keys: set[str] = set()
        self._dir_keys: set[str] = set()
        self.budget = ArchiveBudget(limits, 1)  # replaced per extract() call
        self.dest = Path()
        self._started = False

    # ------------------------------------------------------------------ public

    def extract(self, archive: Path, kind: str, dest: Path, label: str = "upload") -> ExtractionReport:
        if kind not in ("zip", "tar", "gzip", "bz2", "xz", "7z"):
            raise UnsupportedFormatError(f"not an archive kind: {kind}", detected_kind=kind)
        if self._started:
            raise RuntimeError("SafeExtractor instances are single-use")
        self._started = True
        dest.mkdir(parents=True, exist_ok=True)
        self.dest = dest.resolve()
        self.budget = ArchiveBudget(self.limits, os.path.getsize(os_path(archive)))
        try:
            self._extract_one(archive, kind, prefix="", depth=1, label=label)
        except _Halt:
            self._cleanup()
        except LimitExceededError as exc:
            self._issue("F02", f"Archive limit exceeded: {exc.limit}", f"{label}: {exc} (observed {exc.observed})")
            self._halt(f"F02 {exc.limit}")
            self._cleanup()
        self.report.entries_seen = self.budget.entries
        self.report.total_bytes = self.budget.total_bytes
        self.report.findings = self._build_findings(label)
        return self.report

    # ------------------------------------------------------------------ bookkeeping

    def _issue(self, check_id: str, title: str, example: str) -> None:
        self._issues.setdefault((check_id, title), []).append(example)

    def _halt(self, reason: str) -> None:
        self.report.halted = True
        self.report.halt_reason = self.report.halt_reason or reason

    def _skip(self, source: str, reason: str) -> None:
        self.report.skipped.append(SkippedMember(source=source, reason=reason))

    def _cleanup(self) -> None:
        if self._started and self.dest.exists():
            shutil.rmtree(os_path(self.dest), ignore_errors=True)
            self.dest.mkdir(parents=True, exist_ok=True)
        self.report.members = []

    def _build_findings(self, label: str) -> list[Finding]:
        remediation = {
            "F02": "Re-create the archive without excessive compression, nesting or entry counts, "
            "or raise the limit in the scan configuration if the data is trusted.",
            "F03": "Rebuild the archive with plain relative paths and no links or device files.",
            "F04": "Rename the affected files to plain, unique names.",
        }
        out = []
        for (check_id, title), examples in sorted(self._issues.items()):
            out.append(
                make_finding(
                    check_id,
                    title,
                    detail=f"{len(examples)} occurrence(s) in {label}.",
                    evidence={"count": len(examples), "examples": examples[:MAX_EXAMPLES]},
                    location=Location(file=label),
                    remediation=remediation[check_id],
                )
            )
        return sorted(out, key=lambda f: f.severity.rank)

    # ------------------------------------------------------------------ planning

    def _plan_member(
        self,
        raw: str,
        *,
        prefix: str,
        label: str,
        is_dir: bool,
        link_kind: str | None,
        declared_size: int,
        compressed_size: int | None,
        handle: Any,
    ) -> _Planned | None:
        self.budget.add_entry()
        source = f"{label}!{raw}"
        check = analyze_member_path(raw, self.limits.max_member_path_length)
        for reason in check.unsafe:
            self._issue("F03", f"Unsafe archive path: {reason}", source)
        if link_kind is not None:
            self._issue("F03", f"Archive contains a {link_kind}", source)
        if check.unsafe or link_kind is not None:
            self._skip(source, "unsafe path or link/device member")
            return None
        for reason in check.hygiene:
            self._issue("F04", f"Filename hygiene: {reason}", source)
        if not check.ok or check.sanitized is None:
            self._skip(source, "name cannot be sanitized safely")
            return None
        target = prefix + check.sanitized
        key = collision_key(target)
        parent_keys = [collision_key("/".join(target.split("/")[:i])) for i in range(1, target.count("/") + 1)]
        if is_dir:
            if key in self._file_keys:
                self._issue("F04", "Filename collision (case-insensitive or duplicate)", source)
                self._skip(source, "collides with a file")
                return None
            self._dir_keys.add(key)
            self._dir_keys.update(parent_keys)
            return _Planned(raw, target, True, 0, None, handle)
        if key in self._file_keys or key in self._dir_keys or any(p in self._file_keys for p in parent_keys):
            self._issue("F04", "Filename collision (case-insensitive or duplicate)", source)
            self._skip(source, "collides with another member")
            return None
        self.budget.check_declared(declared_size, compressed_size)
        self._file_keys.add(key)
        self._dir_keys.update(parent_keys)
        return _Planned(raw, target, False, declared_size, compressed_size, handle)

    def _check_halt_after_plan(self) -> None:
        if self.halt_on_critical and any(cid == "F03" for cid, _ in self._issues):
            self._halt("F03 unsafe archive member")
            raise _Halt

    # ------------------------------------------------------------------ writing

    def _open_target(self, rel: str) -> tuple[Path, int]:
        target = (self.dest / rel).resolve()
        if self.dest not in target.parents:
            raise _Halt  # cannot happen after sanitizing; defense in depth
        os.makedirs(os_path(target.parent), exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        return target, os.open(os_path(target), flags, 0o600)

    def _write_stream(self, plan: _Planned, stream: IO[bytes], label: str, depth: int) -> None:
        target, fd = self._open_target(plan.target)
        h = hashlib.sha256()
        size = 0
        try:
            with os.fdopen(fd, "wb") as out:
                while True:
                    block = stream.read(BLOCK)
                    if not block:
                        break
                    size += len(block)
                    self.budget.add_bytes(len(block), size, plan.compressed_size)
                    h.update(block)
                    out.write(block)
        except BaseException:
            Path(os_path(target)).unlink(missing_ok=True)
            raise
        self._record(plan, target, size, h.hexdigest(), label, depth)

    def _record(self, plan: _Planned, target: Path, size: int, digest: str, label: str, depth: int) -> None:
        from poisonlens.ingest.sniff import sniff  # local import: sniff imports upload helpers

        source = f"{label}!{plan.raw}"
        nested_kind = sniff(target, plan.target.rsplit("/", 1)[-1]).kind
        if nested_kind in ("zip", "tar", "gzip", "bz2", "xz", "7z"):
            if depth + 1 > self.limits.max_nesting_depth:
                self._issue("F02", "Archive nesting deeper than the limit", f"{source} (depth {depth + 1})")
                self._halt("F02 max_nesting_depth")
                raise _Halt
            try:
                self._extract_one(
                    target, nested_kind, prefix=plan.target + ".extracted/", depth=depth + 1, label=source
                )
            except UnsupportedFormatError as exc:
                # A corrupt inner archive is kept as an opaque member; later checks still see it.
                self._skip(source, f"nested archive not expanded: {exc}")
            else:
                self.report.nested_archives.append(source)
                Path(os_path(target)).unlink()
                return
        self.report.members.append(
            ExtractedMember(path=plan.target, source=source, size=size, sha256=digest, depth=depth)
        )

    # ------------------------------------------------------------------ formats

    def _extract_one(self, path: Path, kind: str, *, prefix: str, depth: int, label: str) -> None:
        if kind == "zip":
            self._zip(path, prefix, depth, label)
        elif kind == "7z":
            self._sevenzip(path, prefix, depth, label)
        else:
            self._tar_or_single(path, kind, prefix, depth, label)

    def _zip(self, path: Path, prefix: str, depth: int, label: str) -> None:
        try:
            zf = zipfile.ZipFile(os_path(path))
        except (zipfile.BadZipFile, OSError) as exc:
            raise UnsupportedFormatError(f"{label}: unreadable ZIP: {exc}", detected_kind="zip") from exc
        with zf:
            plans: list[_Planned] = []
            for info in zf.infolist():
                mode = info.external_attr >> 16
                link_kind = None
                if stat.S_ISLNK(mode):
                    link_kind = "symlink"
                elif stat.S_ISCHR(mode) or stat.S_ISBLK(mode) or stat.S_ISFIFO(mode) or stat.S_ISSOCK(mode):
                    link_kind = "device/special file"
                # orig_filename keeps bytes after a NUL that zipfile truncates in .filename
                plan = self._plan_member(
                    info.orig_filename,
                    prefix=prefix,
                    label=label,
                    is_dir=info.is_dir(),
                    link_kind=link_kind,
                    declared_size=info.file_size,
                    compressed_size=info.compress_size,
                    handle=info,
                )
                if plan is None:
                    continue
                if info.flag_bits & 0x1:
                    self._skip(f"{label}!{info.filename}", "encrypted member")
                    continue
                plans.append(plan)
            self._check_halt_after_plan()
            for plan in plans:
                if plan.is_dir:
                    continue
                try:
                    with zf.open(plan.handle) as stream:
                        self._write_stream(plan, stream, label, depth)
                except (zipfile.BadZipFile, NotImplementedError, OSError) as exc:  # CRC error, method unsupported
                    self._skip(f"{label}!{plan.raw}", f"unreadable member: {type(exc).__name__}: {exc}")

    def _open_decompressed(self, path: Path, kind: str) -> IO[bytes]:
        if kind == "tar":
            return open(os_path(path), "rb")
        result: IO[bytes] = _DECOMPRESSORS[kind](os_path(path), "rb")
        return result

    def _tar_or_single(self, path: Path, kind: str, prefix: str, depth: int, label: str) -> None:
        ceiling = self.limits.max_total_bytes + 64 * 1024 * 1024
        with self._open_decompressed(path, kind) as probe_raw:
            probe = _CountingReader(probe_raw, ceiling, self.budget)
            try:
                head = probe.read(512)
            except (OSError, EOFError, lzma.LZMAError) as exc:
                raise UnsupportedFormatError(f"{label}: corrupt {kind} stream: {exc}", detected_kind=kind) from exc
        is_tar = kind == "tar" or (len(head) >= 262 and head[257:262] == b"ustar")
        if not is_tar:
            self._single(path, kind, prefix, depth, label)
            return

        plans: dict[str, _Planned] = {}
        for member in self._iter_tar(path, kind, ceiling, label):
            link_kind = None
            if member.issym():
                link_kind = "symlink"
            elif member.islnk():
                link_kind = "hardlink"
            elif member.ischr() or member.isblk() or member.isfifo():
                link_kind = "device/special file"
            elif not (member.isreg() or member.isdir()):
                self.budget.add_entry()
                self._skip(f"{label}!{member.name}", f"unsupported tar member type {member.type!r}")
                continue
            plan = self._plan_member(
                member.name,
                prefix=prefix,
                label=label,
                is_dir=member.isdir(),
                link_kind=link_kind,
                declared_size=member.size,
                compressed_size=None,
                handle=member.name,
            )
            if plan is not None and member.name not in plans:
                plans[member.name] = plan
        self._check_halt_after_plan()

        with self._open_decompressed(path, kind) as raw:
            reader = io.BufferedReader(_CountingReader(raw, ceiling, self.budget))
            with tarfile.open(fileobj=reader, mode="r|") as tf:
                for member in tf:
                    plan = plans.pop(member.name, None)
                    if plan is None or plan.is_dir or not member.isreg():
                        continue
                    stream = tf.extractfile(member)
                    if stream is None:
                        continue
                    self._write_stream(plan, stream, label, depth)

    def _iter_tar(self, path: Path, kind: str, ceiling: int, label: str) -> Iterator[tarfile.TarInfo]:
        with self._open_decompressed(path, kind) as raw:
            reader = io.BufferedReader(_CountingReader(raw, ceiling, self.budget))
            try:
                with tarfile.open(fileobj=reader, mode="r|") as tf:
                    yield from tf
            except tarfile.TarError as exc:
                raise UnsupportedFormatError(f"{label}: corrupt tar: {exc}", detected_kind="tar") from exc

    def _single(self, path: Path, kind: str, prefix: str, depth: int, label: str) -> None:
        """gz / bz2 / xz of one file: output name is the label's file name minus the suffix."""
        base = label.rsplit("!", 1)[-1].rsplit("/", 1)[-1]
        for suffix in (".gz", ".gzip", ".bz2", ".xz", ".tgz"):
            if base.lower().endswith(suffix):
                base = base[: -len(suffix)]
                break
        else:
            base = base + ".out"
        plan = self._plan_member(
            base or "decompressed",
            prefix=prefix,
            label=label,
            is_dir=False,
            link_kind=None,
            declared_size=0,
            compressed_size=os.path.getsize(os_path(path)),
            handle=None,
        )
        if plan is None:
            return
        with self._open_decompressed(path, kind) as stream:
            try:
                self._write_stream(plan, stream, label, depth)
            except (OSError, EOFError, lzma.LZMAError) as exc:
                self._skip(f"{label}!{base}", f"corrupt {kind} stream: {exc}")

    def _sevenzip(self, path: Path, prefix: str, depth: int, label: str) -> None:
        try:
            import py7zr
            from py7zr.io import Py7zIO, WriterFactory
        except ImportError as exc:  # optional dependency
            raise UnsupportedFormatError("7z support requires the optional 'py7zr' package") from exc

        with py7zr.SevenZipFile(os_path(path), mode="r") as zf:
            if zf.needs_password():
                self._skip(label, "encrypted 7z archive")
                return
            plans: dict[str, _Planned] = {}
            for info in zf.list():
                plan = self._plan_member(
                    info.filename,
                    prefix=prefix,
                    label=label,
                    is_dir=info.is_directory,
                    link_kind="symlink" if info.is_symlink else None,
                    declared_size=info.uncompressed or 0,
                    compressed_size=None,
                    handle=info.filename,
                )
                if plan is not None and not plan.is_dir:
                    plans[info.filename] = plan
        self._check_halt_after_plan()

        extractor = self
        written: list[tuple[_Planned, Path, int, str]] = []

        class _CappedWriter(Py7zIO):
            def __init__(self, plan: _Planned | None):
                self.plan = plan
                self._n = 0
                self.h = hashlib.sha256()
                self.target: Path | None = None
                self.fh: IO[bytes] | None = None
                if plan is not None:
                    self.target, fd = extractor._open_target(plan.target)
                    self.fh = os.fdopen(fd, "wb")

            def write(self, s: bytes | bytearray) -> int:
                self._n += len(s)
                extractor.budget.add_bytes(len(s), self._n, None)  # discarded bytes still count
                if self.fh is not None:
                    self.h.update(s)
                    self.fh.write(s)
                return len(s)

            def read(self, size: int | None = None) -> bytes:
                return b""

            def seek(self, offset: int, whence: int = 0) -> int:
                return 0

            def flush(self) -> None:
                if self.fh is not None:
                    self.fh.flush()

            def size(self) -> int:
                return self._n

            def close(self) -> None:
                if self.fh is not None and not self.fh.closed:
                    self.fh.close()
                    if self.plan is None or self.target is None:
                        raise RuntimeError("7z writer closed without a target")
                    written.append((self.plan, self.target, self._n, self.h.hexdigest()))

        writers: list[_CappedWriter] = []

        class _Factory(WriterFactory):
            def create(self, filename: str) -> Py7zIO:
                w = _CappedWriter(plans.get(filename))
                writers.append(w)
                return w

        try:
            with py7zr.SevenZipFile(os_path(path), mode="r") as zf:
                zf.extractall(factory=_Factory())  # noqa: S202 - py7zr; every write goes through _CappedWriter
        finally:
            for w in writers:
                w.close()
        for plan, target, size, digest in written:
            self._record(plan, target, size, digest, label, depth)


def safe_extract(
    archive: Path,
    kind: str,
    dest: Path,
    limits: ArchiveLimits,
    *,
    halt_on_critical: bool = True,
    label: str = "upload",
) -> ExtractionReport:
    """Extract ``archive`` (sniffed as ``kind``) into ``dest`` under ``limits``. See module docstring."""
    return SafeExtractor(limits, halt_on_critical=halt_on_critical).extract(archive, kind, dest, label)


__all__ = ["ExtractedMember", "ExtractionReport", "SkippedMember", "safe_extract", "SafeExtractor"]
