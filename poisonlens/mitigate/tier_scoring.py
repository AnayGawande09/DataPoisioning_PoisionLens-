"""Controlled mitigation: 3-tier sample weighting (Keep, Down-weight, Quarantine)."""

from typing import Dict, Any, Tuple, Optional
import numpy as np
import torch


def assign_mitigation_tiers(
    scores: np.ndarray,
    quarantine_ratio: float = 0.05,
    downweight_ratio: float = 0.10,
    downweight_value: float = 0.20,
) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
    """Assign training samples to three tiers based on suspicion scores.
    
    Tiers:
    1. Quarantine (Score >= tau_quarantine): Weight = 0.0 (excluded from training)
    2. Down-weight (tau_down <= Score < tau_quarantine): Weight = downweight_value
    3. Keep (Score < tau_down): Weight = 1.0 (full contribution)
    
    Args:
        scores: 1D array of length N with suspicion scores (higher = more suspicious).
        quarantine_ratio: Fraction of highest suspicion samples to quarantine.
        downweight_ratio: Additional fraction of samples to down-weight.
        downweight_value: Loss scale weight for tier 2 samples (default 0.20).
        
    Returns:
        Tuple of:
            - weights: Float array of shape (N,) with values in {0.0, downweight_value, 1.0}.
            - tier_names: Array of strings of shape (N,) with "quarantine", "downweight", or "keep".
            - info: Metadata dictionary containing thresholds and counts.
    """
    N = len(scores)
    k_quarantine = int(np.ceil(round(quarantine_ratio * N, 6)))
    num_downweight = int(np.ceil(round(downweight_ratio * N, 6)))
    k_downweight = min(N, k_quarantine + num_downweight)
    
    sorted_indices = np.argsort(-scores)  # Highest suspicion first
    
    weights = np.ones(N, dtype=np.float32)
    tier_names = np.array(["keep"] * N, dtype=object)
    
    # Tier 1: Quarantine (top k_quarantine)
    quarantine_indices = sorted_indices[:k_quarantine]
    weights[quarantine_indices] = 0.0
    tier_names[quarantine_indices] = "quarantine"
    
    # Tier 2: Down-weight (from k_quarantine to k_downweight)
    downweight_indices = sorted_indices[k_quarantine:k_downweight]
    weights[downweight_indices] = float(downweight_value)
    tier_names[downweight_indices] = "downweight"
    
    # Tier 3: Keep (remaining)
    keep_indices = sorted_indices[k_downweight:]
    
    tau_quarantine = float(scores[sorted_indices[min(k_quarantine, N - 1)]]) if k_quarantine > 0 else float("inf")
    tau_down = float(scores[sorted_indices[min(k_downweight, N - 1)]]) if k_downweight > 0 else float("inf")
    
    info = {
        "num_quarantined": len(quarantine_indices),
        "num_downweighted": len(downweight_indices),
        "num_kept": len(keep_indices),
        "tau_quarantine": tau_quarantine,
        "tau_down": tau_down,
        "downweight_value": downweight_value,
        "quarantine_mask": (weights == 0.0),
        "downweight_mask": (weights == downweight_value),
        "keep_mask": (weights == 1.0),
    }
    
    return weights, tier_names, info


def assign_hard_deletion(
    scores: np.ndarray,
    drop_ratio: float = 0.05,
) -> Tuple[np.ndarray, np.ndarray, Dict[str, Any]]:
    """Binary hard deletion baseline: top drop_ratio quarantined (0.0), remainder kept (1.0).
    
    Args:
        scores: 1D array of suspicion scores.
        drop_ratio: Fraction of samples to delete.
        
    Returns:
        Tuple of (weights, tier_names, info).
    """
    N = len(scores)
    k_drop = int(np.ceil(round(drop_ratio * N, 6)))
    sorted_indices = np.argsort(-scores)
    
    weights = np.ones(N, dtype=np.float32)
    tier_names = np.array(["keep"] * N, dtype=object)
    
    drop_indices = sorted_indices[:k_drop]
    weights[drop_indices] = 0.0
    tier_names[drop_indices] = "quarantine"
    
    tau_drop = float(scores[sorted_indices[min(k_drop, N - 1)]]) if k_drop > 0 else float("inf")
    
    info = {
        "num_quarantined": len(drop_indices),
        "num_downweighted": 0,
        "num_kept": N - len(drop_indices),
        "tau_quarantine": tau_drop,
        "tau_down": tau_drop,
        "quarantine_mask": (weights == 0.0),
        "keep_mask": (weights == 1.0),
    }
    
    return weights, tier_names, info


def measure_wrongly_quarantined(
    quarantine_mask: np.ndarray,
    gt_poison_mask: np.ndarray,
) -> Dict[str, Any]:
    """Measure the exact count and rate of clean samples wrongly quarantined (False Positives).
    
    Args:
        quarantine_mask: Boolean array indicating quarantined samples.
        gt_poison_mask: Ground truth poison mask.
        
    Returns:
        Dictionary with false positive statistics.
    """
    clean_mask = ~gt_poison_mask
    wrongly_quarantined = quarantine_mask & clean_mask
    fp_count = int(np.sum(wrongly_quarantined))
    total_clean = int(np.sum(clean_mask))
    total_quarantined = int(np.sum(quarantine_mask))
    
    fp_rate = fp_count / max(1, total_clean)
    clean_retention_rate = (total_clean - fp_count) / max(1, total_clean)
    
    return {
        "wrongly_quarantined_count": fp_count,
        "total_clean_samples": total_clean,
        "total_quarantined": total_quarantined,
        "clean_false_positive_rate": fp_rate,
        "clean_retention_rate": clean_retention_rate,
    }
