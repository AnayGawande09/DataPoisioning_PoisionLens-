"""On-disk layout of a scan, with traversal-proof path resolution.

Every scan lives in ``<data_dir>/scans/<scan_id>/``::

    upload/      original upload (random name), never served back raw
    sandbox/     safely-extracted archive members
    canonical/   manifest.parquet, features_raw.*, profile.json
    features/    cached feature matrices (memmap)
    dynamics/    probe training dynamics
    results/     findings, signals, scores, tiers, canary, risk, report
    audit/       ledger.jsonl
    export/      sanitized dataset, weights, quarantine
    events.jsonl progress events (SSE replay)
    state.json   ScanState

``data_dir`` is ``$POISONLENS_DATA_DIR`` if set, else ``<repo>/data``.
"""

from __future__ import annotations

import os
import re
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import unquote

from poisonlens.core.errors import PathSafetyError

SCAN_ID_RE = re.compile(r"^[a-zA-Z0-9_\-]{8,64}$")

SUBDIRS: tuple[str, ...] = (
    "upload",
    "sandbox",
    "canonical",
    "features",
    "dynamics",
    "results",
    "audit",
    "export",
)


def default_data_dir() -> Path:
    env = os.environ.get("POISONLENS_DATA_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "data"


def validate_scan_id(scan_id: str) -> str:
    """Return ``scan_id`` unchanged if it matches ``^[a-zA-Z0-9_\\-]{8,64}$``, else raise."""
    if not isinstance(scan_id, str) or not SCAN_ID_RE.fullmatch(scan_id):
        raise PathSafetyError("invalid scan id: expected 8-64 characters from [A-Za-z0-9_-]")
    return scan_id


def _check_relative(rel: str) -> None:
    """Reject anything that is not a plain relative path made of normal components.

    Checks the raw string and its percent-decoded form (repeatedly, to catch double
    encoding), under both POSIX and Windows rules.
    """
    if not isinstance(rel, str) or rel == "":
        raise PathSafetyError("empty path")
    candidates = {rel}
    decoded = rel
    for _ in range(3):
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
        candidates.add(decoded)
    for cand in candidates:
        if "\x00" in cand:
            raise PathSafetyError("NUL byte in path")
        win = PureWindowsPath(cand)
        posix = PurePosixPath(cand)
        if win.drive or win.root or posix.is_absolute() or cand.startswith(("\\", "/")):
            raise PathSafetyError(f"absolute path not allowed: {rel!r}")
        parts = list(win.parts) + list(posix.parts)
        if any(p == ".." for p in parts):
            raise PathSafetyError(f"parent traversal not allowed: {rel!r}")
        if ":" in cand:  # drive-relative ("C:foo") and NTFS alternate data streams ("x:stream")
            raise PathSafetyError(f"':' not allowed in path: {rel!r}")


class ScanPaths:
    """All filesystem locations for one scan. Construction validates the id and containment."""

    def __init__(self, scan_id: str, data_dir: Path | None = None):
        self.scan_id = validate_scan_id(scan_id)
        self.data_dir = Path(data_dir) if data_dir is not None else default_data_dir()
        self.scans_root = (self.data_dir / "scans").resolve()
        root = (self.scans_root / self.scan_id).resolve()
        if root.parent != self.scans_root:
            raise PathSafetyError("scan directory escapes the scans root")
        self.root = root

    # Fixed sub-directories -------------------------------------------------

    @property
    def upload(self) -> Path:
        return self.root / "upload"

    @property
    def sandbox(self) -> Path:
        return self.root / "sandbox"

    @property
    def canonical(self) -> Path:
        return self.root / "canonical"

    @property
    def features(self) -> Path:
        return self.root / "features"

    @property
    def dynamics(self) -> Path:
        return self.root / "dynamics"

    @property
    def results(self) -> Path:
        return self.root / "results"

    @property
    def audit(self) -> Path:
        return self.root / "audit"

    @property
    def export(self) -> Path:
        return self.root / "export"

    @property
    def events_file(self) -> Path:
        return self.root / "events.jsonl"

    @property
    def state_file(self) -> Path:
        return self.root / "state.json"

    # Helpers ---------------------------------------------------------------

    def ensure(self) -> ScanPaths:
        """Create the scan root and every sub-directory (idempotent)."""
        for name in SUBDIRS:
            (self.root / name).mkdir(parents=True, exist_ok=True)
        return self

    def resolve(self, rel: str) -> Path:
        """Resolve a caller-supplied relative path under the scan root, refusing any escape.

        Lexical checks reject traversal, absolute/drive paths and encoded variants;
        the final ``resolve()`` containment check also defeats symlinks that point outside.
        """
        _check_relative(rel)
        target = (self.root / rel).resolve()
        if target != self.root and self.root not in target.parents:
            raise PathSafetyError(f"path escapes scan directory: {rel!r}")
        return target

    def __repr__(self) -> str:
        return f"ScanPaths({self.scan_id!r}, root={str(self.root)!r})"


def os_path(path: Path | str) -> str:
    r"""Filesystem path string safe for long paths.

    On Windows, absolute paths of 240+ characters get the ``\?\`` extended-length prefix so
    they work regardless of the system's 260-character ``MAX_PATH`` setting. Use it for any
    file operation on extracted members, whose names can be long. Elsewhere it is ``str(path)``.
    """
    s = str(path)
    prefix = "\\\\?\\"  # the four characters \\?\
    if os.name == "nt" and len(s) >= 240 and not s.startswith(prefix):
        s = os.path.abspath(s)
        if s.startswith("\\\\"):  # UNC \\server\share -> \\?\UNC\server\share
            return prefix + "UNC\\" + s[2:]
        return prefix + s
    return s
