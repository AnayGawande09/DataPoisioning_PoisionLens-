"""Trajectory Fingerprint Scoring: explainable, robust aggregation of dynamic training features."""

from typing import Dict, Any, Tuple, List, Optional
import numpy as np
from sklearn.linear_model import LogisticRegression

from poisonlens.detect.dynamics_features import extract_all_trajectory_features
from poisonlens.data.cifar import CIFAR10Subset


FEATURE_NAMES = [
    "first_correct_epoch",
    "forgetting_count",
    "loss_variance",
    "early_grad_norm",
    "knn_disagreement",
]

# Human-readable labels for explainable reporting
FEATURE_DISPLAY_NAMES = {
    "first_correct_epoch": "Delayed Learning",
    "forgetting_count": "High Forgetting",
    "loss_variance": "Loss Instability",
    "early_grad_norm": "High Early Gradient Norm",
    "knn_disagreement": "Feature Neighbor Conflict",
}


def normalize_features_mad(
    features: np.ndarray,
    eps: float = 1e-4,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Robust Median and Median Absolute Deviation (MAD) normalization.
    
    Transforms feature f into a robust z-score:
    z = (f - median(f)) / scale
    where scale = MAD(f) * 1.4826 if MAD > eps, else std(f).
    
    Args:
        features: Array of shape (N, D).
        eps: Small constant to prevent division by zero.
        
    Returns:
        Tuple of (normalized_features, medians, scales).
    """
    medians = np.median(features, axis=0)
    abs_deviations = np.abs(features - medians)
    mads = np.median(abs_deviations, axis=0) * 1.4826
    stds = np.std(features, axis=0)
    
    # When a feature is sparse / discrete (e.g. forgetting count where >50% values are 0),
    # the MAD is 0.0. In such cases, use the standard deviation to preserve relative scale.
    scales = np.where(mads > eps, mads, stds)
    scales = np.maximum(scales, eps)
    normalized = (features - medians) / scales
    return normalized, medians, scales


def fit_validation_weights(
    normalized_features: np.ndarray,
    val_indices: np.ndarray,
    val_labels: np.ndarray,
    feature_names: List[str] = FEATURE_NAMES,
) -> np.ndarray:
    """Fit explainable, non-negative linear weights on a small validation split.
    
    Uses an L2-regularized logistic regression with a non-negativity constraint
    (clipping negative coefficients to zero) so that higher suspicion remains strictly monotonic.
    
    Args:
        normalized_features: Array of shape (N, D).
        val_indices: Indices of samples in the validation split.
        val_labels: Binary poison labels (1 = poison, 0 = clean) for the validation samples.
        feature_names: Ordered list of feature names.
        
    Returns:
        Weight array of shape (D,) summing to 1.0.
    """
    X_val = normalized_features[val_indices]
    y_val = val_labels.astype(int)
    
    # Check if both classes are present in the validation split
    if len(np.unique(y_val)) >= 2:
        clf = LogisticRegression(C=1.0, max_iter=200, solver="lbfgs")
        clf.fit(X_val, y_val)
        raw_weights = clf.coef_[0]
        # Enforce non-negativity (suspicion must not decrease as anomalous metrics increase)
        weights = np.maximum(raw_weights, 0.0)
    else:
        # Default uniform prior if validation set is unlabelled or single-class
        weights = np.ones(len(feature_names), dtype=np.float32)
        
    if np.sum(weights) <= 1e-6:
        weights = np.ones(len(feature_names), dtype=np.float32)
        
    weights = weights / np.sum(weights)
    return weights.astype(np.float32)


def compute_suspicion_scores(
    normalized_features: np.ndarray,
    weights: np.ndarray,
    feature_names: List[str] = FEATURE_NAMES,
    reason_threshold: float = 1.5,
) -> Tuple[np.ndarray, List[List[str]]]:
    """Compute composite suspicion score and per-sample human-readable reasons.
    
    Args:
        normalized_features: Robust z-scores of shape (N, D).
        weights: Feature weights of shape (D,).
        feature_names: List of feature names.
        reason_threshold: Minimum MAD z-score for a feature to be cited in reasons.
        
    Returns:
        Tuple of:
            - scores: 1D array of shape (N,) with composite suspicion score.
            - reasons: List of lists containing textual explanations for each sample.
    """
    num_samples, num_features = normalized_features.shape
    scores = np.dot(normalized_features, weights)
    
    reasons: List[List[str]] = []
    for i in range(num_samples):
        sample_reasons = []
        # Find which features significantly exceed the normal threshold
        for j, fname in enumerate(feature_names):
            z_val = normalized_features[i, j]
            if z_val >= reason_threshold and weights[j] > 0.0:
                display_name = FEATURE_DISPLAY_NAMES.get(fname, fname)
                sample_reasons.append(f"{display_name} (z={z_val:.2f})")
                
        # If no single feature exceeded reason_threshold, cite the top contributing feature
        if not sample_reasons:
            contributions = normalized_features[i] * weights
            top_j = int(np.argmax(contributions))
            display_name = FEATURE_DISPLAY_NAMES.get(feature_names[top_j], feature_names[top_j])
            sample_reasons.append(f"{display_name} (z={normalized_features[i, top_j]:.2f})")
            
        reasons.append(sample_reasons)
        
    return scores, reasons


def detect_by_trajectory_fingerprint(
    loss_history: np.ndarray,
    correct_history: np.ndarray,
    early_model: Any,
    converged_model: Any,
    dataset: CIFAR10Subset,
    drop_ratio: float = 0.05,
    val_indices: Optional[np.ndarray] = None,
    val_labels: Optional[np.ndarray] = None,
    custom_weights: Optional[np.ndarray] = None,
    feature_subset: Optional[List[str]] = None,
    device: Any = "cpu",
    k_neighbors: int = 15,
    raw_features: Optional[Dict[str, np.ndarray]] = None,
) -> Tuple[np.ndarray, np.ndarray, List[List[str]], Dict[str, Any]]:
    """Execute end-to-end Trajectory Fingerprint Scoring detection.
    
    Args:
        loss_history: (num_epochs, N) array.
        correct_history: (num_epochs, N) boolean array.
        early_model: Checkpoint model from epoch 1.
        converged_model: Checkpoint model from final epoch.
        dataset: CIFAR10Subset training dataset.
        drop_ratio: Fraction of top suspicious samples to flag as poison.
        val_indices: Optional validation indices for weight tuning.
        val_labels: Optional validation labels.
        custom_weights: Optional explicit weights array.
        feature_subset: Optional subset of feature names for ablation studies.
        device: Device for inference.
        k_neighbors: Number of neighbors for kNN disagreement.
        raw_features: Optional precomputed raw feature dictionary.
        
    Returns:
        Tuple of (drop_mask, scores, reasons, metadata).
    """
    if raw_features is not None:
        raw_feats_dict = raw_features
    else:
        raw_feats_dict = extract_all_trajectory_features(
            loss_history=loss_history,
            correct_history=correct_history,
            early_model=early_model,
            converged_model=converged_model,
            dataset=dataset,
            device=device,
            k_neighbors=k_neighbors,
        )
    
    active_features = feature_subset if feature_subset is not None else FEATURE_NAMES
    
    # Assemble feature matrix (N, D)
    feature_cols = [raw_feats_dict[name] for name in active_features]
    raw_feature_matrix = np.column_stack(feature_cols)
    
    # Robust MAD normalization
    norm_features, medians, mads = normalize_features_mad(raw_feature_matrix)
    
    # Weight assignment
    if custom_weights is not None:
        weights = custom_weights / np.sum(custom_weights)
    elif val_indices is not None and val_labels is not None:
        weights = fit_validation_weights(norm_features, val_indices, val_labels, active_features)
    else:
        # Default balanced prior: emphasize kNN and early grad norm
        default_prior = {
            "first_correct_epoch": 0.15,
            "forgetting_count": 0.15,
            "loss_variance": 0.15,
            "early_grad_norm": 0.25,
            "knn_disagreement": 0.30,
        }
        w = np.array([default_prior.get(f, 0.20) for f in active_features], dtype=np.float32)
        weights = w / np.sum(w)
        
    scores, reasons = compute_suspicion_scores(
        normalized_features=norm_features,
        weights=weights,
        feature_names=active_features,
    )
    
    # Determine quarantine mask based on top drop_ratio suspicious samples
    N = len(scores)
    k_drop = int(np.ceil(drop_ratio * N))
    sorted_indices = np.argsort(-scores)  # Highest suspicion first
    
    drop_mask = np.zeros(N, dtype=bool)
    if k_drop > 0:
        flagged_idx = sorted_indices[:k_drop]
        drop_mask[flagged_idx] = True
        
    threshold = float(scores[sorted_indices[min(k_drop, N - 1)]]) if k_drop > 0 else 0.0
    
    metadata = {
        "active_features": active_features,
        "weights": {active_features[i]: float(weights[i]) for i in range(len(active_features))},
        "medians": {active_features[i]: float(medians[i]) for i in range(len(active_features))},
        "mads": {active_features[i]: float(mads[i]) for i in range(len(active_features))},
        "threshold": threshold,
        "num_flagged": int(drop_mask.sum()),
    }
    
    return drop_mask, scores, reasons, metadata
