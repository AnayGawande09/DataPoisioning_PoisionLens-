"""Unit tests for Phase 4: Trajectory Fingerprint Scoring."""

import numpy as np
import pytest
import torch
import torch.nn as nn

from poisonlens.detect.dynamics_features import (
    extract_first_correct_epoch,
    extract_forgetting_events,
    extract_loss_dynamics,
    extract_knn_disagreement,
)
from poisonlens.detect.trajectory_scorer import (
    normalize_features_mad,
    fit_validation_weights,
    compute_suspicion_scores,
    detect_by_trajectory_fingerprint,
)
from poisonlens.data.image_dataset import ImageArrayDataset
from poisonlens.models.resnet import create_model


def test_first_correct_epoch():
    # 3 epochs, 4 samples
    correct = np.array([
        [True, False, False, False],
        [True, True,  False, False],
        [True, False, True,  False],
    ])
    first_epoch = extract_first_correct_epoch(correct)
    assert first_epoch[0] == 0.0  # Epoch 0
    assert first_epoch[1] == 1.0  # Epoch 1
    assert first_epoch[2] == 2.0  # Epoch 2
    assert first_epoch[3] == 3.0  # Never (returns num_epochs)


def test_forgetting_events():
    # Sample 0: never forgotten (T -> T -> T)
    # Sample 1: forgotten once (T -> F -> T)
    # Sample 2: forgotten twice (T -> F -> T -> F)
    correct = np.array([
        [True,  True,  True],
        [True,  False, False],
        [True,  True,  True],
        [True,  True,  False],
    ])
    forgetting = extract_forgetting_events(correct)
    assert forgetting[0] == 0.0
    assert forgetting[1] == 1.0
    assert forgetting[2] == 2.0


def test_loss_dynamics():
    # 5 epochs, 2 samples
    # Sample 0: decreasing loss (slope < 0)
    # Sample 1: increasing loss (slope > 0)
    losses = np.array([
        [2.0, 0.5],
        [1.5, 0.8],
        [1.0, 1.2],
        [0.8, 1.6],
        [0.5, 2.0],
    ])
    var, slope = extract_loss_dynamics(losses)
    assert var.shape == (2,)
    assert slope[0] < 0.0  # Decreasing loss
    assert slope[1] > 0.0  # Increasing loss


def test_knn_disagreement():
    # 4 samples: 2 in cluster A (pos [0,0]), 2 in cluster B (pos [10,10])
    features = np.array([
        [0.0, 0.0],
        [0.1, 0.1],
        [10.0, 10.0],
        [10.1, 10.1],
    ], dtype=np.float32)
    # Target: samples 0 and 1 have label 0, sample 2 has label 1, sample 3 has poisoned label 0!
    targets = np.array([0, 0, 1, 0])
    
    # With k=1, sample 3's nearest neighbor is sample 2 (label 1), but sample 3 target is 0. Disagreement = 1.0!
    disagreement = extract_knn_disagreement(features, targets, k=1)
    assert disagreement[0] == 0.0
    assert disagreement[1] == 0.0
    assert disagreement[2] == 1.0  # NN is sample 3 (label 0) != 1
    assert disagreement[3] == 1.0  # NN is sample 2 (label 1) != 0


def test_mad_normalization():
    # Feature with a heavy outlier
    x = np.array([[1.8], [2.0], [2.1], [1.9], [100.0]])
    norm, medians, mads = normalize_features_mad(x)
    assert medians[0] == pytest.approx(2.0, abs=0.1)
    # Normal samples stay close to 0, outlier has large robust z-score
    assert abs(norm[0, 0]) < 2.0
    assert norm[4, 0] > 10.0


def test_compute_suspicion_scores_and_reasons():
    norm_feats = np.array([
        [0.1, 0.2, 0.0, 0.1, 0.2],   # Clean sample
        [0.5, 0.1, 0.0, 3.5, 4.2],   # Poisoned sample (high early grad norm, high kNN)
    ])
    weights = np.array([0.1, 0.1, 0.1, 0.35, 0.35])
    feature_names = [
        "first_correct_epoch",
        "forgetting_count",
        "loss_variance",
        "early_grad_norm",
        "knn_disagreement",
    ]
    scores, reasons = compute_suspicion_scores(norm_feats, weights, feature_names, reason_threshold=2.0)
    
    assert scores[1] > scores[0]
    assert len(reasons[1]) >= 2
    # Check that high features are cited in the explanation
    reason_str = " ".join(reasons[1])
    assert "Early Gradient Norm" in reason_str
    assert "Feature Neighbor Conflict" in reason_str


def test_end_to_end_detector():
    N = 50
    images = np.zeros((N, 32, 32, 3), dtype=np.uint8)
    targets = np.random.randint(0, 10, size=N)
    sub = ImageArrayDataset(images, targets, list(range(N)), list(range(N)))
    
    early_model = create_model(10)
    converged_model = create_model(10)
    
    losses = np.random.uniform(0.1, 2.0, size=(5, N)).astype(np.float32)
    correct = np.random.choice([True, False], size=(5, N))
    
    drop_mask, scores, reasons, meta = detect_by_trajectory_fingerprint(
        loss_history=losses,
        correct_history=correct,
        early_model=early_model,
        converged_model=converged_model,
        dataset=sub,
        drop_ratio=0.10,
    )
    
    assert len(drop_mask) == N
    assert drop_mask.sum() == 5  # 10% of 50
    assert len(scores) == N
    assert len(reasons) == N
    assert "weights" in meta
