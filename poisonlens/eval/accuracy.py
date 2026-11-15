"""Clean accuracy evaluation for any loader yielding (x, y, sample_id)."""

from typing import Tuple

import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader


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
