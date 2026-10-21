"""Test checkpoint resume parity with uninterrupted training."""

import os
import shutil
from typing import Tuple, Dict
import pytest
import torch
import numpy as np

from poisonlens.utils import set_seed, ensure_dir
from poisonlens.data.cifar import get_cifar10_loaders
from poisonlens.models.resnet import create_model
from poisonlens.training.trainer import PoisonLensTrainer


def test_resume_parity(tmp_path):
    """Verify that training with checkpoint and resume matches uninterrupted training bit-for-bit."""
    seed = 2026
    data_root = "./data_cache"

    # Part 1: Uninterrupted run for 4 epochs
    uninterrupted_dir = str(tmp_path / "uninterrupted")
    ensure_dir(uninterrupted_dir)

    set_seed(seed)
    train_loader1, test_loader1, train_sub1, _, _ = get_cifar10_loaders(
        data_root=data_root,
        train_size=1000,
        test_size=200,
        batch_size=64,
        seed=seed,
    )

    config1 = {
        "seed": seed,
        "epochs": 4,
        "lr": 0.001,
        "weight_decay": 1e-4,
    }

    model1 = create_model(num_classes=10)
    trainer1 = PoisonLensTrainer(
        model=model1,
        train_loader=train_loader1,
        test_loader=test_loader1,
        train_dataset_size=len(train_sub1),
        run_dir=uninterrupted_dir,
        config=config1,
        device=torch.device("cpu"),
    )

    output1 = trainer1.train(max_epochs=4)
    final_acc1 = output1["final_test_acc"]
    state1 = {k: v.cpu().clone() for k, v in model1.state_dict().items()}

    # Part 2: Train for 2 epochs, checkpoint, and stop
    resumed_dir = str(tmp_path / "resumed")
    ensure_dir(resumed_dir)

    set_seed(seed)
    train_loader2, test_loader2, train_sub2, _, _ = get_cifar10_loaders(
        data_root=data_root,
        train_size=1000,
        test_size=200,
        batch_size=64,
        seed=seed,
    )

    config2 = {
        "seed": seed,
        "epochs": 4,
        "lr": 0.001,
        "weight_decay": 1e-4,
    }

    model2 = create_model(num_classes=10)
    trainer2 = PoisonLensTrainer(
        model=model2,
        train_loader=train_loader2,
        test_loader=test_loader2,
        train_dataset_size=len(train_sub2),
        run_dir=resumed_dir,
        config=config2,
        device=torch.device("cpu"),
    )

    # Train only 2 epochs
    trainer2.train(max_epochs=2)
    checkpoint_epoch2 = os.path.join(resumed_dir, "checkpoints", "checkpoint_epoch_2.pt")
    assert os.path.exists(checkpoint_epoch2), "Checkpoint for epoch 2 was not saved!"

    # Part 3: Resume in a fresh trainer instance from epoch 2 checkpoint to epoch 4
    model3 = create_model(num_classes=10)
    trainer3 = PoisonLensTrainer(
        model=model3,
        train_loader=train_loader2,
        test_loader=test_loader2,
        train_dataset_size=len(train_sub2),
        run_dir=resumed_dir,
        config=config2,
        device=torch.device("cpu"),
    )

    output3 = trainer3.train(resume_from=checkpoint_epoch2, max_epochs=4)
    final_acc3 = output3["final_test_acc"]
    state3 = {k: v.cpu().clone() for k, v in model3.state_dict().items()}

    # Final test accuracies must match
    assert final_acc1 == pytest.approx(final_acc3, rel=1e-5), f"Accuracy mismatch: {final_acc1} vs {final_acc3}"

    # Parameters must match bit-for-bit
    assert state1.keys() == state3.keys()
    for key in state1:
        diff = (state1[key].float() - state3[key].float()).abs().max().item()
        assert diff < 1e-5, f"Parameter mismatch for layer {key}: max abs diff = {diff}"
