"""Security and validation utilities for the PoisonLens API.

Identifier regex and path-containment guards. The v2 artifact allowlist is
added with the scan API (Phase 10); see docs/MIGRATION_NOTES.md for what was
removed from v1.
"""

from __future__ import annotations

import re
from pathlib import Path

from fastapi import HTTPException

# Safe identifier pattern (v2 tightens this to 8-64 chars for scan ids in Phase 1).
SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")


def validate_identifier(value: str, kind: str = "id") -> str:
    """Reject identifiers that are empty or contain anything but ``[A-Za-z0-9_-]``."""
    if not value or not SAFE_ID_PATTERN.match(value):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid {kind}. Only letters, digits, underscores and hyphens are allowed.",
        )
    return value


def safe_resolve_path(base_dir: str | Path, target_name: str) -> Path:
    """Resolve ``target_name`` under ``base_dir`` and refuse anything that escapes it."""
    base = Path(base_dir).resolve()
    target = (base / target_name).resolve()
    if target != base and base not in target.parents:
        raise HTTPException(status_code=400, detail="Path traversal attempt detected.")
    return target
