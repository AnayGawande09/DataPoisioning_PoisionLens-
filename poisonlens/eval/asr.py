"""Evaluation metrics: Clean Test Accuracy and Attack Success Rate (ASR)."""

from typing import Tuple, Callable, Optional
import numpy as np
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader, TensorDataset

from poisonlens.data.cifar import CIFAR10Subset, CIFAR10_MEAN, CIFAR10_STD


@torch.no_grad()
def evaluate_clean_accuracy(
    model: torch.nn.Module,
    test_loader: DataLoader,
    device: torch.device = torch.device("cpu"),
) -> Tuple[float, float]:
    """Calculate clean accuracy and average cross-entropy loss."""
    model.eval()
    total_correct = 0
    total_loss = 0.0
    total_samples = 0

    for batch_images, batch_targets, _ in test_loader:
        batch_images = batch_images.to(device)
        batch_targets = batch_targets.to(device)

        logits = model(batch_images)
        loss = F.cross_entropy(logits, batch_targets, reduction="sum")
        preds = logits.argmax(dim=-1)

        total_loss += loss.item()
        total_correct += (preds == batch_targets).sum().item()
        total_samples += batch_targets.size(0)

    acc = total_correct / max(1, total_samples)
    avg_loss = total_loss / max(1, total_samples)
    return float(acc), float(avg_loss)


@torch.no_grad()
def evaluate_backdoor_asr(
    model: torch.nn.Module,
    test_dataset: CIFAR10Subset,
    trigger_fn: Callable[[np.ndarray], np.ndarray],
    target_class: int = 0,
    batch_size: int = 128,
    device: torch.device = torch.device("cpu"),
) -> float:
    """
    Calculate Attack Success Rate (ASR) for backdoor attacks (BadNets, Blended).
    ASR is evaluated strictly on test samples that do NOT originally belong to target_class.
    ASR = fraction of triggered test samples classified as target_class.
    """
    model.eval()
    non_target_indices = np.where(test_dataset.targets != target_class)[0]
    if len(non_target_indices) == 0:
        return 0.0

    # Extract non-target clean images and apply trigger
    clean_images = test_dataset.images[non_target_indices]
    triggered_images = trigger_fn(clean_images)

    # Normalize to float tensor
    mean = torch.tensor(CIFAR10_MEAN, dtype=torch.float32).view(1, 3, 1, 1)
    std = torch.tensor(CIFAR10_STD, dtype=torch.float32).view(1, 3, 1, 1)
    tensors = torch.from_numpy(triggered_images).permute(0, 3, 1, 2).float() / 255.0
    normalized_tensors = (tensors - mean) / std

    # Evaluate in batches
    target_matches = 0
    total = len(non_target_indices)

    for i in range(0, total, batch_size):
        batch = normalized_tensors[i : i + batch_size].to(device)
        logits = model(batch)
        preds = logits.argmax(dim=-1)
        target_matches += (preds == target_class).sum().item()

    asr = target_matches / total
    return float(asr)


@torch.no_grad()
def evaluate_label_flip_asr(
    model: torch.nn.Module,
    test_dataset: CIFAR10Subset,
    source_class: int = 3,
    target_class: int = 5,
    batch_size: int = 128,
    device: torch.device = torch.device("cpu"),
) -> float:
    """
    Calculate Attack Success Rate (ASR) for targeted label flipping.
    ASR = fraction of clean source_class test samples misclassified as target_class.
    """
    model.eval()
    source_indices = np.where(test_dataset.targets == source_class)[0]
    if len(source_indices) == 0:
        return 0.0

    # Test tensors are already normalized in test_dataset.tensors
    source_tensors = test_dataset.tensors[source_indices]

    target_matches = 0
    total = len(source_indices)

    for i in range(0, total, batch_size):
        batch = source_tensors[i : i + batch_size].to(device)
        logits = model(batch)
        preds = logits.argmax(dim=-1)
        target_matches += (preds == target_class).sum().item()

    asr = target_matches / total
    return float(asr)
