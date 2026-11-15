"""Unit tests for scoring reproducibility with fixed seeds."""

import numpy as np
import pytest
import torch

from poisonlens.data.image_dataset import ImageArrayDataset
from poisonlens.models.resnet import create_model
from poisonlens.detect.trajectory_scorer import detect_by_trajectory_fingerprint


def test_scoring_reproducibility():
    """Verify that two runs with the same seed yield 100% identical quarantine lists."""
    N = 100
    images = np.zeros((N, 32, 32, 3), dtype=np.uint8)
    targets = np.random.randint(0, 10, size=N)
    sub = ImageArrayDataset(images, targets, list(range(N)), list(range(N)))
    
    losses = np.random.uniform(0.1, 2.0, size=(5, N)).astype(np.float32)
    correct = np.random.choice([True, False], size=(5, N))
    
    # Run 1 with seed 42
    torch.manual_seed(42)
    early_1 = create_model(10)
    conv_1 = create_model(10)
    drop_mask_1, scores_1, reasons_1, meta_1 = detect_by_trajectory_fingerprint(
        loss_history=losses,
        correct_history=correct,
        early_model=early_1,
        converged_model=conv_1,
        dataset=sub,
        drop_ratio=0.10,
    )
    
    # Run 2 with seed 42
    torch.manual_seed(42)
    early_2 = create_model(10)
    conv_2 = create_model(10)
    drop_mask_2, scores_2, reasons_2, meta_2 = detect_by_trajectory_fingerprint(
        loss_history=losses,
        correct_history=correct,
        early_model=early_2,
        converged_model=conv_2,
        dataset=sub,
        drop_ratio=0.10,
    )
    
    quarantine_1 = np.where(drop_mask_1)[0].tolist()
    quarantine_2 = np.where(drop_mask_2)[0].tolist()
    
    # Exact match check
    assert quarantine_1 == quarantine_2
    assert np.allclose(scores_1, scores_2, atol=1e-6)
    assert reasons_1 == reasons_2
