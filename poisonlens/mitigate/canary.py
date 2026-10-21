"""Clean canary set guardrail with automatic checkpoint rollback."""

from typing import Dict, Any, Tuple, Optional
import os
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader

from poisonlens.data.cifar import CIFAR10Subset
from poisonlens.eval.asr import evaluate_clean_accuracy


class CanaryGuard:
    """Evaluates model performance on a held-out clean canary set (~200 verified samples)
    and executes automatic rollback if mitigation degrades clean generalization beyond tolerance.
    """

    def __init__(
        self,
        canary_dataset: CIFAR10Subset,
        tolerance: float = 0.03,  # Max allowable canary accuracy drop (3.0%)
        device: torch.device = torch.device("cpu"),
        batch_size: int = 64,
    ):
        self.canary_dataset = canary_dataset
        self.tolerance = tolerance
        self.device = device
        self.loader = DataLoader(canary_dataset, batch_size=batch_size, shuffle=False, num_workers=0)
        self.baseline_accuracy: Optional[float] = None

    def establish_baseline(self, model: nn.Module) -> float:
        """Measure clean canary accuracy on the baseline / pre-mitigation model."""
        acc, _ = evaluate_clean_accuracy(model, self.loader, device=self.device)
        self.baseline_accuracy = acc
        return acc

    def evaluate(self, model: nn.Module) -> float:
        """Measure current canary accuracy."""
        acc, _ = evaluate_clean_accuracy(model, self.loader, device=self.device)
        return acc

    def check_health(
        self,
        current_acc: float,
        baseline_acc: Optional[float] = None,
    ) -> Tuple[bool, float]:
        """Check if current accuracy is within acceptable tolerance of baseline.
        
        Returns:
            Tuple of (is_healthy, accuracy_delta).
            is_healthy is True if accuracy drop does not exceed tolerance.
            accuracy_delta is (current_acc - baseline_acc).
        """
        ref_acc = baseline_acc if baseline_acc is not None else self.baseline_accuracy
        if ref_acc is None:
            return True, 0.0
            
        delta = current_acc - ref_acc
        drop = -delta
        is_healthy = bool(drop <= self.tolerance)
        return is_healthy, float(delta)

    def verify_and_rollback(
        self,
        candidate_model: nn.Module,
        backup_checkpoint_path: str,
        current_quarantine_ratio: float = 0.05,
    ) -> Tuple[bool, float, float, Dict[str, Any]]:
        """Verify candidate model against canary set and automatically roll back if damaged.
        
        Args:
            candidate_model: The newly trained/mitigated model.
            backup_checkpoint_path: Path to checkpoint to restore if canary is harmed.
            current_quarantine_ratio: The threshold ratio that produced this model.
            
        Returns:
            Tuple of:
                - rolled_back: Boolean indicating whether rollback occurred.
                - canary_acc: Evaluated canary accuracy before rollback.
                - canary_delta: Accuracy drop or gain relative to baseline.
                - decision_info: Dictionary detailing the guardrail decision.
        """
        canary_acc = self.evaluate(candidate_model)
        is_healthy, delta = self.check_health(canary_acc)
        
        if not is_healthy:
            # Automatic rollback triggered
            ckpt = torch.load(backup_checkpoint_path, map_location=self.device, weights_only=False)
            if "model_state_dict" in ckpt:
                candidate_model.load_state_dict(ckpt["model_state_dict"])
            else:
                candidate_model.load_state_dict(ckpt)
                
            loosened_ratio = max(0.01, current_quarantine_ratio * 0.5)
            
            decision_info = {
                "action": "ROLLBACK_TRIGGERED",
                "reason": f"Canary accuracy dropped by {-delta*100:.2f}%, exceeding {self.tolerance*100:.1f}% tolerance.",
                "baseline_canary_acc": self.baseline_accuracy,
                "mitigated_canary_acc": canary_acc,
                "canary_delta": delta,
                "tolerance": self.tolerance,
                "rolled_back_to": backup_checkpoint_path,
                "suggested_loosened_ratio": loosened_ratio,
            }
            return True, canary_acc, delta, decision_info
        else:
            decision_info = {
                "action": "APPROVED",
                "reason": f"Canary health preserved (delta: {delta*100:+.2f}% within tolerance {self.tolerance*100:.1f}%).",
                "baseline_canary_acc": self.baseline_accuracy,
                "mitigated_canary_acc": canary_acc,
                "canary_delta": delta,
                "tolerance": self.tolerance,
            }
            return False, canary_acc, delta, decision_info
