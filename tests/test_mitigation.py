"""Unit tests for Phase 5: Controlled mitigation, canary guardrails, and per-class impacts."""

import os
import numpy as np
import pytest
import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from poisonlens.mitigate.tier_scoring import (
    assign_mitigation_tiers,
    assign_hard_deletion,
    measure_wrongly_quarantined,
)
from poisonlens.mitigate.canary import CanaryGuard
from poisonlens.eval.per_class import (
    evaluate_per_class_accuracy,
    compute_per_class_impact,
)
from poisonlens.data.cifar import CIFAR10Subset
from poisonlens.models.resnet import create_model


def test_3_tier_assignment():
    scores = np.array([0.1, 0.2, 0.5, 0.8, 1.2, 2.5, 3.0, 4.5, 5.0, 9.0])  # 10 samples
    # 10% quarantine (1 sample: 9.0)
    # 20% downweight (2 samples: 5.0, 4.5)
    # 70% keep (7 samples)
    weights, tiers, info = assign_mitigation_tiers(
        scores, quarantine_ratio=0.10, downweight_ratio=0.20, downweight_value=0.25
    )
    
    assert len(weights) == 10
    assert info["num_quarantined"] == 1
    assert info["num_downweighted"] == 2
    assert info["num_kept"] == 7
    
    # Highest score (sample 9) must be quarantined
    assert weights[9] == 0.0
    assert tiers[9] == "quarantine"
    
    # Next highest (samples 8 and 7) must be downweighted
    assert weights[8] == 0.25
    assert weights[7] == 0.25
    assert tiers[8] == "downweight"
    assert tiers[7] == "downweight"
    
    # Lowest score must be kept
    assert weights[0] == 1.0
    assert tiers[0] == "keep"


def test_hard_deletion_assignment():
    scores = np.linspace(0, 10, 100)
    weights, tiers, info = assign_hard_deletion(scores, drop_ratio=0.10)
    
    assert len(weights) == 100
    assert info["num_quarantined"] == 10
    assert info["num_downweighted"] == 0
    assert info["num_kept"] == 90
    assert weights[-10:].tolist() == [0.0] * 10
    assert weights[:-10].tolist() == [1.0] * 90


def test_measure_wrongly_quarantined():
    # 10 samples: first 2 are poison, remaining 8 are clean
    gt_poison = np.array([True, True, False, False, False, False, False, False, False, False])
    # Quarantine flagged sample 0 (TP), sample 1 (TP), and sample 2 (FP)
    quarantine = np.array([True, True, True, False, False, False, False, False, False, False])
    
    stats = measure_wrongly_quarantined(quarantine, gt_poison)
    assert stats["wrongly_quarantined_count"] == 1  # Sample 2
    assert stats["total_clean_samples"] == 8
    assert stats["total_quarantined"] == 3
    assert stats["clean_false_positive_rate"] == pytest.approx(1 / 8)
    assert stats["clean_retention_rate"] == pytest.approx(7 / 8)


def test_canary_guard_health_and_rollback(tmp_path):
    N = 20
    images = np.zeros((N, 32, 32, 3), dtype=np.uint8)
    targets = np.zeros(N, dtype=np.int64)
    canary_sub = CIFAR10Subset(images, targets, list(range(N)), list(range(N)))
    
    guard = CanaryGuard(canary_sub, tolerance=0.03)
    
    # Fake model
    model = create_model(10)
    
    # Save a backup checkpoint
    backup_path = str(tmp_path / "backup.pt")
    torch.save({"model_state_dict": model.state_dict()}, backup_path)
    
    # Establish baseline
    base_acc = guard.establish_baseline(model)
    assert guard.baseline_accuracy == base_acc
    
    # Health check within tolerance
    healthy, delta = guard.check_health(base_acc - 0.01)
    assert healthy is True
    assert delta == pytest.approx(-0.01)
    
    # Health check exceeding tolerance
    unhealthy, drop_delta = guard.check_health(base_acc - 0.05)
    assert unhealthy is False
    assert drop_delta == pytest.approx(-0.05)


def test_per_class_accuracy_and_impact():
    baseline_per_class = {c: 0.60 for c in range(10)}
    mitigated_per_class = {c: 0.60 for c in range(10)}
    mitigated_per_class[3] = 0.40  # Class 3 suffered a severe drop (-20%)
    mitigated_per_class[5] = 0.65  # Class 5 gained (+5%)
    
    impact = compute_per_class_impact(baseline_per_class, mitigated_per_class)
    assert impact["worst_harmed_class"] == 3
    assert impact["worst_class_drop"] == pytest.approx(-0.20)
    assert impact["best_improved_class"] == 5
    assert impact["best_class_gain"] == pytest.approx(0.05)
