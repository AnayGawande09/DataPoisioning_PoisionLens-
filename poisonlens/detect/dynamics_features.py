"""Training dynamics feature extraction for Trajectory Fingerprint Scoring.

Features extracted:
1. Epoch of first correct prediction
2. Forgetting events count (correct -> incorrect transitions)
3. Loss curve trajectory dynamics (variance and slope across epochs)
4. Gradient-norm proxy at an early checkpoint
5. Feature-space kNN neighbour disagreement in penultimate representations
"""

from typing import Dict, Any, Tuple, Optional
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import DataLoader
from sklearn.neighbors import NearestNeighbors

from poisonlens.data.image_dataset import ImageArrayDataset


def extract_first_correct_epoch(correct_history: np.ndarray) -> np.ndarray:
    """Find the earliest epoch where each sample was predicted correctly.
    
    Args:
        correct_history: Boolean array of shape (num_epochs, num_samples).
        
    Returns:
        Array of shape (num_samples,) containing 0-indexed first correct epoch,
        or num_epochs if never correctly predicted.
    """
    num_epochs, num_samples = correct_history.shape
    first_epoch = np.full(num_samples, num_epochs, dtype=np.float32)
    
    for epoch in range(num_epochs):
        mask = correct_history[epoch] & (first_epoch == num_epochs)
        first_epoch[mask] = epoch
        
    return first_epoch


def extract_forgetting_events(correct_history: np.ndarray) -> np.ndarray:
    """Count number of times a sample transitioned from correct to incorrect.
    
    Reference: Toneva et al., "An Empirical Study of Example Forgetting during Deep Neural Network Learning" (ICLR 2019).
    
    Args:
        correct_history: Boolean array of shape (num_epochs, num_samples).
        
    Returns:
        Array of shape (num_samples,) with integer count of forgetting events.
    """
    num_epochs, num_samples = correct_history.shape
    if num_epochs <= 1:
        return np.zeros(num_samples, dtype=np.float32)
        
    prev = correct_history[:-1]
    curr = correct_history[1:]
    flips = (prev & (~curr)).astype(np.int32)
    return np.sum(flips, axis=0).astype(np.float32)


def extract_loss_dynamics(loss_history: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
    """Compute per-sample loss trajectory variance and linear trend slope across epochs.
    
    Args:
        loss_history: Float array of shape (num_epochs, num_samples).
        
    Returns:
        Tuple of (loss_variance, loss_slope), each of shape (num_samples,).
        Positive slope indicates loss increased or failed to descend properly.
    """
    num_epochs, num_samples = loss_history.shape
    loss_var = np.var(loss_history, axis=0).astype(np.float32)
    
    if num_epochs <= 1:
        loss_slope = np.zeros(num_samples, dtype=np.float32)
    else:
        # Vectorized linear regression slope: cov(x, y) / var(x)
        x = np.arange(num_epochs, dtype=np.float32)
        x_centered = x - np.mean(x)
        x_var = np.sum(x_centered ** 2)
        
        y_centered = loss_history - np.mean(loss_history, axis=0, keepdims=True)
        loss_slope = np.sum(x_centered[:, None] * y_centered, axis=0) / max(1e-8, x_var)
        
    return loss_var, loss_slope.astype(np.float32)


def extract_early_gradient_norm(
    model: nn.Module,
    dataset: ImageArrayDataset,
    device: torch.device = torch.device("cpu"),
    batch_size: int = 128,
) -> np.ndarray:
    """Compute per-sample gradient-norm proxy at an early training checkpoint.
    
    For a linear classification layer with weight W, the loss gradient for sample i is:
    dL/dW_i = (p_i - y_i) h_i^T
    where p_i = softmax(z_i) and h_i is the penultimate feature vector.
    The Frobenius norm of this rank-1 matrix is exactly:
    ||dL/dW_i||_F = ||p_i - y_i||_2 * ||h_i||_2.
    
    This provides an exact per-sample gradient norm with zero backward pass overhead.
    
    Args:
        model: Early-epoch model checkpoint (e.g. Epoch 1).
        dataset: Training dataset subset.
        device: Computation device.
        batch_size: Batch size for forward pass.
        
    Returns:
        Array of shape (len(dataset),) with gradient norm proxies.
    """
    model.eval()
    model.to(device)
    
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False, num_workers=0)
    grad_norms = np.zeros(len(dataset), dtype=np.float32)
    
    with torch.no_grad():
        for batch_images, batch_targets, batch_sids in loader:
            batch_images = batch_images.to(device)
            batch_targets = batch_targets.to(device)
            
            features = model.extract_features(batch_images)  # (B, 128)
            logits = model.fc(features)  # (B, num_classes)
            probs = F.softmax(logits, dim=-1)
            
            # One-hot target encoding
            one_hot = torch.zeros_like(probs)
            one_hot.scatter_(1, batch_targets.unsqueeze(1), 1.0)
            
            # ||p_i - y_i||_2
            logit_grad_norm = torch.norm(probs - one_hot, p=2, dim=1)  # (B,)
            # ||h_i||_2
            feat_norm = torch.norm(features, p=2, dim=1)  # (B,)
            
            per_sample_norm = (logit_grad_norm * feat_norm).cpu().numpy()
            grad_norms[batch_sids.numpy()] = per_sample_norm
            
    return grad_norms


def extract_knn_disagreement(
    features: np.ndarray,
    targets: np.ndarray,
    k: int = 15,
) -> np.ndarray:
    """Compute feature-space kNN label disagreement within the penultimate layer.
    
    For each sample i, finds its k nearest neighbours (excluding self) in feature space
    and calculates the fraction of neighbours whose label differs from target_i.
    
    Args:
        features: Penultimate representations of shape (N, D).
        targets: Target labels of shape (N,).
        k: Number of nearest neighbours.
        
    Returns:
        Array of shape (N,) with disagreement ratio in [0, 1].
    """
    num_samples = len(features)
    k = min(k, num_samples - 1)
    if k <= 0:
        return np.zeros(num_samples, dtype=np.float32)
        
    # Standardize features dimension-wise for stable Euclidean distance
    feat_mean = np.mean(features, axis=0, keepdims=True)
    feat_std = np.std(features, axis=0, keepdims=True) + 1e-8
    standardized_feats = (features - feat_mean) / feat_std
    
    # Fit kNN (k+1 to include query sample itself)
    nn = NearestNeighbors(n_neighbors=k + 1, algorithm="auto", metric="euclidean", n_jobs=-1)
    nn.fit(standardized_feats)
    
    indices = nn.kneighbors(standardized_feats, return_distance=False)  # (N, k+1)
    # Exclude self (first column)
    neighbor_indices = indices[:, 1:]  # (N, k)
    
    neighbor_labels = targets[neighbor_indices]  # (N, k)
    query_labels = targets[:, None]  # (N, 1)
    
    disagreements = (neighbor_labels != query_labels).astype(np.float32)
    disagreement_ratio = np.mean(disagreements, axis=1)  # (N,)
    
    return disagreement_ratio.astype(np.float32)


def extract_all_trajectory_features(
    loss_history: np.ndarray,
    correct_history: np.ndarray,
    early_model: nn.Module,
    converged_model: nn.Module,
    dataset: ImageArrayDataset,
    device: torch.device = torch.device("cpu"),
    k_neighbors: int = 15,
) -> Dict[str, np.ndarray]:
    """Extract all 5 dynamic features for the dataset.
    
    Returns:
        Dictionary mapping feature name to 1D numpy array of length N.
    """
    first_correct = extract_first_correct_epoch(correct_history)
    forgetting = extract_forgetting_events(correct_history)
    loss_var, loss_slope = extract_loss_dynamics(loss_history)
    early_grad_norm = extract_early_gradient_norm(early_model, dataset, device=device)
    
    # Extract penultimate features from converged model for kNN analysis
    converged_model.eval()
    converged_model.to(device)
    loader = DataLoader(dataset, batch_size=128, shuffle=False, num_workers=0)
    features_list = []
    
    with torch.no_grad():
        for batch_images, _, _ in loader:
            feats = converged_model.extract_features(batch_images.to(device))
            features_list.append(feats.cpu().numpy())
    converged_features = np.concatenate(features_list, axis=0)
    
    knn_disagreement = extract_knn_disagreement(
        features=converged_features,
        targets=dataset.targets,
        k=k_neighbors,
    )
    
    return {
        "first_correct_epoch": first_correct,
        "forgetting_count": forgetting,
        "loss_variance": loss_var,
        "loss_slope": loss_slope,
        "early_grad_norm": early_grad_norm,
        "knn_disagreement": knn_disagreement,
    }
