"""Security and validation utilities for PoisonLens API."""

import re
import os
from fastapi import HTTPException

# Safe regex pattern for run IDs and identifiers
SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-]+$")

# Strict allowlist of preset names
ALLOWED_PRESETS = {
    "clean_baseline",
    "attack_badnets_5",
    "attack_blended_5",
    "attack_labelflip_5",
    "attack_labelflip_10",
}

# Strict allowlist of downloadable artifacts to prevent unauthorized file access
ALLOWED_ARTIFACTS = {
    "pipeline_results.json",
    "audit_log.jsonl",
    "tampered_audit_log.jsonl",
    "config.yaml",
    "run_info.json",
    "results.json",
}


def validate_run_id(run_id: str) -> str:
    """Validate run_id against safe character pattern to prevent path traversal."""
    if not run_id or not SAFE_ID_PATTERN.match(run_id):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid run_id '{run_id}'. Run IDs must contain only alphanumeric characters, underscores, and hyphens.",
        )
    if ".." in run_id or "/" in run_id or "\\" in run_id:
        raise HTTPException(status_code=400, detail="Path traversal sequences are strictly forbidden.")
    return run_id


def validate_preset_name(preset_name: str) -> str:
    """Validate preset_name against strict allowlist."""
    if preset_name not in ALLOWED_PRESETS:
        raise HTTPException(
            status_code=400,
            detail=f"Preset '{preset_name}' is not in the allowlist of supported configurations. Allowed: {sorted(list(ALLOWED_PRESETS))}",
        )
    return preset_name


def validate_artifact_name(artifact_name: str) -> str:
    """Validate artifact filename against allowed artifact list."""
    if not artifact_name or artifact_name not in ALLOWED_ARTIFACTS:
        raise HTTPException(
            status_code=400,
            detail=f"Artifact '{artifact_name}' is not accessible. Allowed artifacts: {sorted(list(ALLOWED_ARTIFACTS))}",
        )
    return artifact_name


def safe_resolve_path(base_dir: str, target_name: str) -> str:
    """Safely resolve path ensuring it remains strictly inside base_dir."""
    resolved_base = os.path.abspath(base_dir)
    target_path = os.path.abspath(os.path.join(resolved_base, target_name))
    if not target_path.startswith(resolved_base):
        raise HTTPException(status_code=400, detail="Path traversal attempt detected.")
    return target_path
