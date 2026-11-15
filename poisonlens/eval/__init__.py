"""Evaluation helpers used by product code (accuracy, per-class impact).

Attack-success-rate metrics need known attacks and live in ``poisonlens.bench.eval_asr``.
"""

from poisonlens.eval.accuracy import evaluate_clean_accuracy
from poisonlens.eval.per_class import (
    evaluate_per_class_accuracy,
    compute_per_class_impact,
)

__all__ = [
    "evaluate_clean_accuracy",
    "evaluate_per_class_accuracy",
    "compute_per_class_impact",
]
