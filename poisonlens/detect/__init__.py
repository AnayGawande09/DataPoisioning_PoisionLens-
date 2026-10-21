"""Poison detection methods, features, metrics, and scorers."""

from poisonlens.detect.metrics import compute_detection_metrics
from poisonlens.detect.loss_filter import detect_by_loss_threshold, compute_sample_losses
from poisonlens.detect.activation_clustering import (
    detect_by_activation_clustering,
    extract_all_penultimate_features,
)
from poisonlens.detect.dynamics_features import (
    extract_first_correct_epoch,
    extract_forgetting_events,
    extract_loss_dynamics,
    extract_early_gradient_norm,
    extract_knn_disagreement,
    extract_all_trajectory_features,
)
from poisonlens.detect.trajectory_scorer import (
    normalize_features_mad,
    fit_validation_weights,
    compute_suspicion_scores,
    detect_by_trajectory_fingerprint,
    FEATURE_NAMES,
)

__all__ = [
    "compute_detection_metrics",
    "detect_by_loss_threshold",
    "compute_sample_losses",
    "detect_by_activation_clustering",
    "extract_all_penultimate_features",
    "extract_first_correct_epoch",
    "extract_forgetting_events",
    "extract_loss_dynamics",
    "extract_early_gradient_norm",
    "extract_knn_disagreement",
    "extract_all_trajectory_features",
    "normalize_features_mad",
    "fit_validation_weights",
    "compute_suspicion_scores",
    "detect_by_trajectory_fingerprint",
    "FEATURE_NAMES",
]
