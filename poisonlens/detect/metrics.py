"""Evaluation metrics for poison detection: Precision, Recall, F1, and Confusion Counts."""

from typing import Dict, Any, Tuple
import numpy as np


def compute_detection_metrics(ground_truth_mask: np.ndarray, predicted_mask: np.ndarray) -> Dict[str, float]:
    """
    Compute Precision, Recall, and F1 score of poison detection against ground truth.
    ground_truth_mask: boolean array (True = poison, False = clean)
    predicted_mask: boolean array (True = flagged as poison, False = clean)
    """
    gt = ground_truth_mask.astype(bool)
    pred = predicted_mask.astype(bool)

    tp = int(np.logical_and(gt, pred).sum())
    fp = int(np.logical_and(~gt, pred).sum())
    fn = int(np.logical_and(gt, ~pred).sum())
    tn = int(np.logical_and(~gt, ~pred).sum())

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "total_flagged": int(pred.sum()),
        "total_true_poison": int(gt.sum()),
    }
