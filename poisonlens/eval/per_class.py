"""Per-class accuracy evaluation and collateral damage impact analysis."""

from typing import Dict, Any, Tuple
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from poisonlens.data.image_dataset import ImageArrayDataset


@torch.no_grad()
def evaluate_per_class_accuracy(
    model: nn.Module,
    loader: DataLoader,
    num_classes: int = 10,
    device: torch.device = torch.device("cpu"),
) -> Dict[int, float]:
    """Compute exact classification accuracy independently for each class.
    
    Args:
        model: PyTorch classification model.
        loader: DataLoader for test or validation set.
        num_classes: Number of distinct classes.
        device: Computation device.
        
    Returns:
        Dictionary mapping class index (0..num_classes-1) to accuracy in [0.0, 1.0].
    """
    model.eval()
    model.to(device)
    
    class_correct = np.zeros(num_classes, dtype=np.int64)
    class_total = np.zeros(num_classes, dtype=np.int64)
    
    for batch_images, batch_targets, _ in loader:
        batch_images = batch_images.to(device)
        batch_targets = batch_targets.to(device)
        
        logits = model(batch_images)
        preds = logits.argmax(dim=-1)
        
        targets_np = batch_targets.cpu().numpy()
        preds_np = preds.cpu().numpy()
        
        for c in range(num_classes):
            c_mask = (targets_np == c)
            class_total[c] += np.sum(c_mask)
            class_correct[c] += np.sum((preds_np == c) & c_mask)
            
    per_class_acc: Dict[int, float] = {}
    for c in range(num_classes):
        per_class_acc[c] = float(class_correct[c] / max(1, class_total[c]))
        
    return per_class_acc


def compute_per_class_impact(
    baseline_per_class: Dict[int, float],
    mitigated_per_class: Dict[int, float],
) -> Dict[str, Any]:
    """Analyze the per-class accuracy shift induced by data mitigation.
    
    Identifies which classes suffered disproportionate collateral damage
    from wrongly quarantined clean training samples.
    
    Args:
        baseline_per_class: Per-class accuracy of undefended / baseline model.
        mitigated_per_class: Per-class accuracy of mitigated model.
        
    Returns:
        Dictionary containing per-class deltas, most-harmed class, and spread.
    """
    deltas = {}
    for c in baseline_per_class:
        deltas[c] = float(mitigated_per_class[c] - baseline_per_class[c])
        
    delta_values = list(deltas.values())
    worst_class = int(np.argmin(delta_values))
    worst_drop = float(delta_values[worst_class])
    
    best_class = int(np.argmax(delta_values))
    best_gain = float(delta_values[best_class])
    
    mean_delta = float(np.mean(delta_values))
    std_delta = float(np.std(delta_values))
    
    return {
        "per_class_deltas": deltas,
        "worst_harmed_class": worst_class,
        "worst_class_drop": worst_drop,
        "best_improved_class": best_class,
        "best_class_gain": best_gain,
        "mean_class_delta": mean_delta,
        "std_class_delta": std_delta,
    }
