"""Backend data and execution services for PoisonLens."""

import os
import glob
import json
import yaml
import time
from typing import Dict, Any, List, Optional, Tuple
import numpy as np
from fastapi import HTTPException

from backend.security import (
    validate_run_id,
    validate_artifact_name,
    safe_resolve_path,
    ALLOWED_ARTIFACTS,
)

# Base paths
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RUNS_DIR = os.path.join(ROOT_DIR, "runs")
CONFIGS_DIR = os.path.join(ROOT_DIR, "configs")


def get_all_presets() -> List[Dict[str, Any]]:
    """Load all experiment presets from configs/ with human-readable descriptions and metadata."""
    presets = []
    preset_meta = {
        "clean_baseline": {
            "name": "Clean Baseline",
            "category": "Baseline",
            "threat_level": "None",
            "description": "Standard training on 10,000 clean CIFAR-10 images. Establishes the clean upper-bound accuracy without adversarial perturbation.",
            "attack_type": "none",
            "badge_color": "cyan",
        },
        "attack_labelflip_5": {
            "name": "Targeted Label Flip (5%)",
            "category": "Data Poisoning",
            "threat_level": "Medium",
            "description": "5% of training samples have source class 3 (Cat) flipped to target class 5 (Dog) without pixel modification.",
            "attack_type": "label_flip",
            "badge_color": "violet",
        },
        "attack_labelflip_10": {
            "name": "Targeted Label Flip (10%)",
            "category": "Data Poisoning",
            "threat_level": "High",
            "description": "10% of training samples have source class 3 (Cat) flipped to target class 5 (Dog). Tests aggressive label corruption.",
            "attack_type": "label_flip",
            "badge_color": "rose",
        },
        "attack_badnets_5": {
            "name": "BadNets Backdoor (5%)",
            "category": "Backdoor",
            "threat_level": "Critical",
            "description": "5% of samples injected with a 3x3 bottom-right white patch trigger and relabeled to target class 0 (Airplane).",
            "attack_type": "badnets",
            "badge_color": "rose",
        },
        "attack_blended_5": {
            "name": "Blended Backdoor (5%)",
            "category": "Stealthy Backdoor",
            "threat_level": "Critical",
            "description": "5% of samples blended with a static noise pattern (alpha=0.20) and relabeled to target class 0. Extremely stealthy.",
            "attack_type": "blended",
            "badge_color": "amber",
        },
    }

    yaml_files = sorted(glob.glob(os.path.join(CONFIGS_DIR, "*.yaml")))
    for yf in yaml_files:
        preset_id = os.path.splitext(os.path.basename(yf))[0]
        try:
            with open(yf, "r", encoding="utf-8") as f:
                cfg = yaml.safe_load(f) or {}
        except Exception:
            cfg = {}

        meta = preset_meta.get(preset_id, {
            "name": preset_id.replace("_", " ").title(),
            "category": "Custom",
            "threat_level": "Unknown",
            "description": "Configured experiment preset.",
            "attack_type": cfg.get("attack", "custom"),
            "badge_color": "cyan",
        })

        presets.append({
            "id": preset_id,
            "filename": os.path.basename(yf),
            "name": meta["name"],
            "category": meta["category"],
            "threat_level": meta["threat_level"],
            "description": meta["description"],
            "badge_color": meta["badge_color"],
            "attack_type": cfg.get("attack", "none"),
            "poison_rate": cfg.get("poison_rate", 0.0),
            "target_class": cfg.get("target_class"),
            "source_class": cfg.get("source_class"),
            "patch_size": cfg.get("patch_size"),
            "alpha": cfg.get("alpha"),
            "epochs": cfg.get("epochs", 10),
            "batch_size": cfg.get("batch_size", 128),
            "learning_rate": cfg.get("lr", 0.001),
            "weight_decay": cfg.get("weight_decay", 0.0001),
            "device": cfg.get("device", "cpu"),
            "dataset": "CIFAR-10",
            "model": "SmallResNet (~308k params)",
            "is_supported": True,
            "raw_config": cfg,
        })

    return presets


def list_completed_runs() -> List[Dict[str, Any]]:
    """List all available run directories and summarize their status and metrics."""
    runs = []
    if not os.path.exists(RUNS_DIR):
        return runs

    for item in os.listdir(RUNS_DIR):
        run_path = os.path.join(RUNS_DIR, item)
        if not os.path.isdir(run_path):
            continue

        pipeline_results_path = os.path.join(run_path, "pipeline_results.json")
        config_path = os.path.join(run_path, "config.yaml")
        run_info_path = os.path.join(run_path, "run_info.json")
        audit_path = os.path.join(run_path, "audit_log.jsonl")

        status = "UNKNOWN"
        results = None
        run_info = {}
        config = {}

        if os.path.exists(pipeline_results_path):
            try:
                with open(pipeline_results_path, "r", encoding="utf-8") as f:
                    results = json.load(f)
                status = "COMPLETED"
            except Exception:
                status = "CORRUPT"

        if os.path.exists(run_info_path):
            try:
                with open(run_info_path, "r", encoding="utf-8") as f:
                    run_info = json.load(f)
            except Exception:
                pass

        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config = yaml.safe_load(f) or {}
            except Exception:
                pass

        # If it has config but no results, maybe it was an intermediate run
        if status == "UNKNOWN" and os.path.exists(config_path):
            status = "PARTIAL"

        # Calculate directory modified time
        mtime = os.path.getmtime(run_path)
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))

        attack_type = config.get("attack", run_info.get("attack_type", "unknown"))
        poison_rate = config.get("poison_rate", run_info.get("poison_rate", 0.0))

        runs.append({
            "run_id": item,
            "status": status,
            "timestamp": timestamp,
            "attack_type": attack_type,
            "poison_rate": poison_rate,
            "has_audit_log": os.path.exists(audit_path),
            "has_pipeline_results": results is not None,
            "baseline_clean_acc": results.get("baseline_metrics", {}).get("clean_acc") if results else None,
            "mitigated_clean_acc": results.get("mitigated_metrics", {}).get("clean_acc") if results else None,
            "baseline_asr": results.get("baseline_metrics", {}).get("asr") if results else None,
            "mitigated_asr": results.get("mitigated_metrics", {}).get("asr") if results else None,
            "guardrail_action": results.get("guardrail_decision", {}).get("action") if results else None,
            "total_time_seconds": results.get("total_time_seconds") if results else None,
        })

    # Sort newest first
    runs.sort(key=lambda x: x["timestamp"], reverse=True)
    return runs


def get_run_details(run_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full details of a specific run."""
    validate_run_id(run_id)
    run_path = os.path.join(RUNS_DIR, run_id)
    if not os.path.exists(run_path):
        return None

    pipeline_results_path = os.path.join(run_path, "pipeline_results.json")
    config_path = os.path.join(run_path, "config.yaml")
    run_info_path = os.path.join(run_path, "run_info.json")
    audit_path = os.path.join(run_path, "audit_log.jsonl")
    tampered_audit_path = os.path.join(run_path, "tampered_audit_log.jsonl")

    results = {}
    if os.path.exists(pipeline_results_path):
        try:
            with open(pipeline_results_path, "r", encoding="utf-8") as f:
                results = json.load(f)
        except Exception:
            pass

    config = {}
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
        except Exception:
            pass

    run_info = {}
    if os.path.exists(run_info_path):
        try:
            with open(run_info_path, "r", encoding="utf-8") as f:
                run_info = json.load(f)
        except Exception:
            pass

    # Count audit entries
    total_audit_entries = 0
    decision_counts = {"keep": 0, "downweight": 0, "quarantine": 0}
    if os.path.exists(audit_path):
        with open(audit_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    total_audit_entries += 1
                    try:
                        entry = json.loads(line)
                        d = entry.get("decision", "keep").lower()
                        decision_counts[d] = decision_counts.get(d, 0) + 1
                    except Exception:
                        pass

    return {
        "run_id": run_id,
        "config": config,
        "run_info": run_info,
        "results": results,
        "has_audit_log": os.path.exists(audit_path),
        "has_tampered_audit_log": os.path.exists(tampered_audit_path),
        "total_audit_entries": total_audit_entries,
        "decision_counts": decision_counts,
    }


def get_run_samples(
    run_id: str,
    limit: int = 50,
    offset: int = 0,
    decision: Optional[str] = None,
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    search: Optional[str] = None,
    ground_truth_only: bool = False,
) -> Dict[str, Any]:
    """Parse audit_log.jsonl and optional poison_mask.npy to provide sample explorer data."""
    validate_run_id(run_id)
    run_path = os.path.join(RUNS_DIR, run_id)
    if not os.path.exists(run_path):
        raise HTTPException(status_code=404, detail=f"Run directory '{run_id}' not found.")

    audit_path = os.path.join(run_path, "audit_log.jsonl")
    poison_mask_path = os.path.join(run_path, "poison_mask.npy")

    if not os.path.exists(audit_path):
        return {"total": 0, "items": [], "decision_breakdown": {}}

    poison_mask = None
    if os.path.exists(poison_mask_path):
        try:
            poison_mask = np.load(poison_mask_path)
        except Exception:
            pass

    matched_items = []
    decision_breakdown = {"keep": 0, "downweight": 0, "quarantine": 0}

    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except Exception:
                continue

            dec = entry.get("decision", "keep").lower()
            decision_breakdown[dec] = decision_breakdown.get(dec, 0) + 1

            sample_id = entry.get("sample_id", 0)
            score = float(entry.get("score", 0.0))
            reasons = entry.get("reasons", [])

            # Ground truth if available
            is_ground_truth_poison = None
            if poison_mask is not None and 0 <= sample_id < len(poison_mask):
                is_ground_truth_poison = bool(poison_mask[sample_id])

            # Apply filters
            if decision and decision != "all" and dec != decision.lower():
                continue
            if min_score is not None and score < min_score:
                continue
            if max_score is not None and score > max_score:
                continue
            if ground_truth_only and not is_ground_truth_poison:
                continue
            if search:
                s_lower = search.lower()
                matches_id = str(sample_id) == s_lower or f"#{sample_id}" == s_lower
                matches_reason = any(s_lower in r.lower() for r in reasons)
                matches_hash = s_lower in entry.get("entry_hash", "").lower()
                if not (matches_id or matches_reason or matches_hash):
                    continue

            matched_items.append({
                "sample_id": sample_id,
                "score": score,
                "decision": dec,
                "sample_weight": float(entry.get("sample_weight", 1.0)),
                "reasons": reasons,
                "entry_hash": entry.get("entry_hash", "")[:12] + "...",
                "full_entry_hash": entry.get("entry_hash", ""),
                "timestamp": entry.get("timestamp"),
                "is_ground_truth_poison": is_ground_truth_poison,
            })

    total_matched = len(matched_items)
    # Sort suspicious first (highest score descending)
    matched_items.sort(key=lambda x: x["score"], reverse=True)
    paginated = matched_items[offset : offset + limit]

    return {
        "total": total_matched,
        "offset": offset,
        "limit": limit,
        "items": paginated,
        "decision_breakdown": decision_breakdown,
    }


def get_sample_detail(run_id: str, sample_id: int) -> Optional[Dict[str, Any]]:
    """Retrieve detailed per-sample training dynamics (loss history, predictions, correctness)."""
    validate_run_id(run_id)
    if sample_id < 0 or sample_id > 100000:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid sample_id {sample_id}. Must be a non-negative integer within valid range.",
        )

    run_path = os.path.join(RUNS_DIR, run_id)
    if not os.path.exists(run_path):
        raise HTTPException(status_code=404, detail=f"Run directory '{run_id}' not found.")

    audit_path = os.path.join(run_path, "audit_log.jsonl")
    dynamics_path = os.path.join(run_path, "training_dynamics.npz")
    poison_mask_path = os.path.join(run_path, "poison_mask.npy")

    if not os.path.exists(audit_path):
        raise HTTPException(status_code=404, detail=f"Audit log not found for run '{run_id}'.")

    # Find audit entry
    sample_entry = None
    with open(audit_path, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            entry = json.loads(line)
            if entry.get("sample_id") == sample_id:
                sample_entry = entry
                break

    if not sample_entry:
        return None

    # Ground truth
    is_ground_truth_poison = None
    if os.path.exists(poison_mask_path):
        try:
            p_mask = np.load(poison_mask_path)
            if 0 <= sample_id < len(p_mask):
                is_ground_truth_poison = bool(p_mask[sample_id])
        except Exception:
            pass

    # Extract dynamics if available
    loss_curve = []
    preds_history = []
    correct_history = []
    epochs_count = 10

    if os.path.exists(dynamics_path):
        try:
            dyn = np.load(dynamics_path)
            if "losses" in dyn:
                losses = dyn["losses"]  # shape: (epochs, samples)
                if sample_id < losses.shape[1]:
                    loss_curve = [round(float(l), 4) for l in losses[:, sample_id]]
            if "preds" in dyn:
                preds = dyn["preds"]
                if sample_id < preds.shape[1]:
                    preds_history = [int(p) for p in preds[:, sample_id]]
            if "correct" in dyn:
                correct = dyn["correct"]
                if sample_id < correct.shape[1]:
                    correct_history = [bool(c) for c in correct[:, sample_id]]
            epochs_count = len(loss_curve) if loss_curve else 10
        except Exception:
            pass

    return {
        "sample_id": sample_id,
        "score": float(sample_entry.get("score", 0.0)),
        "decision": sample_entry.get("decision", "keep"),
        "sample_weight": float(sample_entry.get("sample_weight", 1.0)),
        "reasons": sample_entry.get("reasons", []),
        "entry_hash": sample_entry.get("entry_hash"),
        "previous_hash": sample_entry.get("previous_hash"),
        "config_hash": sample_entry.get("config_hash"),
        "timestamp": sample_entry.get("timestamp"),
        "is_ground_truth_poison": is_ground_truth_poison,
        "loss_curve": loss_curve,
        "preds_history": preds_history,
        "correct_history": correct_history,
        "epochs_count": epochs_count,
    }


def verify_audit_log_file(run_id: str, use_tampered: bool = False) -> Dict[str, Any]:
    """Verify hash-chain integrity of audit_log.jsonl or tampered_audit_log.jsonl."""
    validate_run_id(run_id)
    from poisonlens.audit.log import verify_audit_log

    run_path = os.path.join(RUNS_DIR, run_id)
    if not os.path.exists(run_path):
        raise HTTPException(status_code=404, detail=f"Run directory '{run_id}' not found.")

    filename = "tampered_audit_log.jsonl" if use_tampered else "audit_log.jsonl"
    log_path = os.path.join(run_path, filename)

    if not os.path.exists(log_path):
        raise HTTPException(
            status_code=404,
            detail=f"Audit log file '{filename}' does not exist for run '{run_id}'.",
        )

    total = 0
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                total += 1

    is_valid, broken_idx, verify_msg = verify_audit_log(log_path)
    msg = (
        f"Cryptographic verification SUCCESSFUL: All {total:,} SHA-256 hash-chain links intact."
        if is_valid
        else f"TAMPERING DETECTED: Hash chain verification failed at sequence index #{broken_idx}. Cryptographic link mismatch!"
    )

    return {
        "is_valid": is_valid,
        "message": msg,
        "raw_verifier_message": verify_msg,
        "total_entries": total,
        "broken_index": broken_idx,
        "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "filename": filename,
    }


def get_audit_entries_paginated(run_id: str, limit: int = 20, offset: int = 0) -> Dict[str, Any]:
    """Fetch paginated audit entries for visualization."""
    validate_run_id(run_id)
    run_path = os.path.join(RUNS_DIR, run_id)
    if not os.path.exists(run_path):
        raise HTTPException(status_code=404, detail=f"Run directory '{run_id}' not found.")

    audit_path = os.path.join(run_path, "audit_log.jsonl")

    if not os.path.exists(audit_path):
        raise HTTPException(
            status_code=404,
            detail=f"Audit log file 'audit_log.jsonl' does not exist for run '{run_id}'.",
        )

    entries = []
    total = 0
    with open(audit_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f):
            total += 1
            if offset <= idx < offset + limit:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "entries": entries,
    }


def get_master_benchmarks() -> List[Dict[str, Any]]:
    """Return empirical benchmark data from runs/final_master_benchmark.json."""
    benchmark_path = os.path.join(RUNS_DIR, "final_master_benchmark.json")
    if os.path.exists(benchmark_path):
        try:
            with open(benchmark_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def get_run_results_data(run_id: str) -> Dict[str, Any]:
    """Retrieve genuine pipeline_results.json for a given run."""
    validate_run_id(run_id)
    run_path = os.path.join(RUNS_DIR, run_id)
    if not os.path.exists(run_path):
        raise HTTPException(status_code=404, detail=f"Run directory '{run_id}' not found.")

    results_path = os.path.join(run_path, "pipeline_results.json")
    if not os.path.exists(results_path):
        # Check if run is active
        raise HTTPException(
            status_code=404,
            detail=f"Experiment results 'pipeline_results.json' not found for run '{run_id}'. The run may still be in progress or failed.",
        )

    with open(results_path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_run_artifacts_list(run_id: str) -> List[Dict[str, Any]]:
    """List all available safe artifacts for a specific run."""
    validate_run_id(run_id)
    run_path = os.path.join(RUNS_DIR, run_id)
    if not os.path.exists(run_path):
        raise HTTPException(status_code=404, detail=f"Run directory '{run_id}' not found.")

    artifacts = []
    for item in os.listdir(run_path):
        item_path = os.path.join(run_path, item)
        if os.path.isfile(item_path):
            is_downloadable = item in ALLOWED_ARTIFACTS
            size_bytes = os.path.getsize(item_path)
            mtime = os.path.getmtime(item_path)
            modified_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(mtime))
            artifacts.append({
                "filename": item,
                "size_bytes": size_bytes,
                "modified_at": modified_at,
                "is_downloadable": is_downloadable,
            })
    return sorted(artifacts, key=lambda x: x["filename"])


def get_safe_artifact_file_path(run_id: str, artifact_name: str) -> str:
    """Validate and return safe path to artifact file."""
    validate_run_id(run_id)
    validate_artifact_name(artifact_name)
    run_path = os.path.join(RUNS_DIR, run_id)
    if not os.path.exists(run_path):
        raise HTTPException(status_code=404, detail=f"Run directory '{run_id}' not found.")

    target_path = safe_resolve_path(run_path, artifact_name)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail=f"Artifact '{artifact_name}' does not exist for run '{run_id}'.")
    return target_path
