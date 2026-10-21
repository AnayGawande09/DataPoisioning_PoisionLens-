"""Test determinism of PoisonLens training pipeline."""

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


def train_short_run(seed: int, run_dir: str, epochs: int = 2) -> Tuple[float, Dict[str, torch.Tensor]]:
    """Helper to train a short run and return test accuracy plus parameter state dict."""
    set_seed(seed)
    ensure_dir(run_dir)

    train_loader, test_loader, train_subset, test_subset, _ = get_cifar10_loaders(
        data_root="./data_cache",
        train_size=1000,
        test_size=200,
        batch_size=64,
        seed=seed,
    )

    config = {
        "seed": seed,
        "epochs": epochs,
        "lr": 0.001,
        "weight_decay": 1e-4,
    }

    model = create_model(num_classes=10)
    trainer = PoisonLensTrainer(
        model=model,
        train_loader=train_loader,
        test_loader=test_loader,
        train_dataset_size=len(train_subset),
        run_dir=run_dir,
        config=config,
        device=torch.device("cpu"),
    )

    output = trainer.train()
    state_dict = {k: v.cpu().clone() for k, v in model.state_dict().items()}
    return output["final_test_acc"], state_dict


def test_determinism(tmp_path):
    """Verify that identical seeds produce identical model weights and test accuracy."""
    run_dir1 = str(tmp_path / "run1")
    run_dir2 = str(tmp_path / "run2")

    acc1, state1 = train_short_run(seed=1337, run_dir=run_dir1, epochs=2)
    acc2, state2 = train_short_run(seed=1337, run_dir=run_dir2, epochs=2)

    # Test accuracy must match exactly
    assert acc1 == pytest.approx(acc2, rel=1e-5), f"Accuracy mismatch: {acc1} vs {acc2}"

    # Every parameter tensor must match exactly
    assert state1.keys() == state2.keys()
    for key in state1:
        diff = (state1[key].float() - state2[key].float()).abs().max().item()
        assert diff < 1e-5, f"Parameter mismatch for layer {key}: max abs diff = {diff}"
