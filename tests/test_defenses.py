"""Unit tests for baseline defenses (Loss Threshold and Activation Clustering)."""

import numpy as np
import pytest
import torch

from poisonlens.detect.metrics import compute_detection_metrics
from poisonlens.detect.loss_filter import detect_by_loss_threshold
from poisonlens.detect.activation_clustering import detect_by_activation_clustering
from poisonlens.models.resnet import create_model
from poisonlens.data.cifar import CIFAR10Subset


def test_detection_metrics():
    gt = np.array([True, True, False, False, True])
    pred = np.array([True, False, True, False, True])

    metrics = compute_detection_metrics(gt, pred)
    assert metrics["tp"] == 2
    assert metrics["fp"] == 1
    assert metrics["fn"] == 1
    assert metrics["tn"] == 1
    assert metrics["precision"] == pytest.approx(2 / 3)
    assert metrics["recall"] == pytest.approx(2 / 3)
    assert metrics["f1"] == pytest.approx(2 / 3)


def test_loss_filter():
    # Synthetic dataset
    N = 100
    images = np.zeros((N, 32, 32, 3), dtype=np.uint8)
    targets = np.random.randint(0, 10, size=N)
    sub = CIFAR10Subset(images, targets, list(range(N)), list(range(N)))

    # Synthetic losses
    losses = np.linspace(0.1, 5.0, N)

    mask, returned_losses = detect_by_loss_threshold(
        model=None,
        dataset=sub,
        drop_ratio=0.10,
        losses=losses,
    )

    assert len(mask) == N
    assert mask.sum() == 10  # 10% of 100
    # Highest loss items should be flagged
    assert mask[-10:].all()
    assert not mask[:-10].any()


def test_activation_clustering():
    N = 100
    images = np.zeros((N, 32, 32, 3), dtype=np.uint8)
    # 50 in class 0, 50 in class 1
    targets = np.array([0] * 50 + [1] * 50)
    sub = CIFAR10Subset(images, targets, list(range(N)), list(range(N)))

    # Create synthetic bimodal features for class 0 (40 clean samples around [0,0...], 10 poison around [10,10...])
    features = np.zeros((N, 128), dtype=np.float32)
    features[:40] += np.random.normal(0, 0.1, size=(40, 128))
    features[40:50] += 10.0 + np.random.normal(0, 0.1, size=(10, 128))  # Backdoor cluster
    features[50:] += np.random.normal(0, 0.1, size=(50, 128))  # Class 1 clean

    mask, info = detect_by_activation_clustering(
        model=None,
        dataset=sub,
        num_classes=2,
        pca_components=5,
        silhouette_threshold=0.10,
        features=features,
    )

    assert len(mask) == N
    assert 0 in info
    # The 10 backdoor samples in class 0 should be flagged
    assert mask[40:50].all()
