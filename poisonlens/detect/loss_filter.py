"""Loss-threshold filtering defense: identifies and drops highest-loss samples."""

from typing import Tuple, Optional
import numpy as np
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader
from poisonlens.data.cifar import CIFAR10Subset


@torch.no_grad()
def compute_sample_losses(
    model: torch.nn.Module,
    dataset: CIFAR10Subset,
    batch_size: int = 128,
    device: torch.device = torch.device("cpu"),
) -> np.ndarray:
    """Compute per-sample cross entropy loss across the dataset using the given model."""
    model.eval()
    total = len(dataset)
    losses = np.zeros(total, dtype=np.float32)

    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False, num_workers=0)
    for batch_images, batch_targets, batch_sample_ids in loader:
        batch_images = batch_images.to(device)
        batch_targets = batch_targets.to(device)

        logits = model(batch_images)
        loss_unreduced = F.cross_entropy(logits, batch_targets, reduction="none")

        s_ids = batch_sample_ids.cpu().numpy()
        losses[s_ids] = loss_unreduced.cpu().numpy()

    return losses


def detect_by_loss_threshold(
    model: torch.nn.Module,
    dataset: CIFAR10Subset,
    drop_ratio: float = 0.05,
    losses: Optional[np.ndarray] = None,
    device: torch.device = torch.device("cpu"),
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Detect poison by flagging the top (drop_ratio * 100)% highest-loss training samples.
    Returns:
        predicted_mask: Boolean array of length N (True = flagged as poison).
        losses: Array of per-sample loss values.
    """
    if losses is None:
        losses = compute_sample_losses(model, dataset, device=device)

    total_samples = len(dataset)
    k = int(total_samples * drop_ratio)

    # Find indices of the top k highest losses
    top_loss_indices = np.argsort(losses)[-k:]

    predicted_mask = np.zeros(total_samples, dtype=bool)
    predicted_mask[top_loss_indices] = True

    return predicted_mask, losses
