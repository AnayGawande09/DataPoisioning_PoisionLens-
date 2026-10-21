"""Activation Clustering defense: 2-means clustering on penultimate-layer features per class."""

from typing import Tuple, Dict, Any, Optional
import numpy as np
import torch
from torch.utils.data import DataLoader
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score

from poisonlens.data.cifar import CIFAR10Subset


@torch.no_grad()
def extract_all_penultimate_features(
    model: torch.nn.Module,
    dataset: CIFAR10Subset,
    batch_size: int = 128,
    device: torch.device = torch.device("cpu"),
) -> np.ndarray:
    """Extract penultimate-layer (128-dim) features for all samples in the dataset."""
    model.eval()
    total = len(dataset)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False, num_workers=0)

    all_features = []
    all_sample_ids = []

    for batch_images, _, batch_sample_ids in loader:
        batch_images = batch_images.to(device)
        features = model.extract_features(batch_images)
        all_features.append(features.cpu().numpy())
        all_sample_ids.append(batch_sample_ids.numpy())

    features_arr = np.concatenate(all_features, axis=0)
    sample_ids_arr = np.concatenate(all_sample_ids, axis=0)

    # Sort in canonical sample_id order
    sorted_features = np.zeros_like(features_arr)
    sorted_features[sample_ids_arr] = features_arr
    return sorted_features


def detect_by_activation_clustering(
    model: torch.nn.Module,
    dataset: CIFAR10Subset,
    num_classes: int = 10,
    pca_components: int = 10,
    silhouette_threshold: float = 0.12,
    max_poison_cluster_ratio: float = 0.35,
    features: Optional[np.ndarray] = None,
    device: torch.device = torch.device("cpu"),
    seed: int = 42,
) -> Tuple[np.ndarray, Dict[str, Any]]:
    """
    Activation Clustering (Chen et al., 2018):
    Performs 2-means clustering on penultimate features for each class.
    Flags minority clusters in classes with distinct bimodal separation.
    Returns:
        predicted_mask: Boolean array of length N (True = flagged as poison).
        cluster_info: Per-class clustering diagnostics.
    """
    if features is None:
        features = extract_all_penultimate_features(model, dataset, device=device)

    total_samples = len(dataset)
    predicted_mask = np.zeros(total_samples, dtype=bool)
    targets = np.array(dataset.targets)

    cluster_info = {}

    for c in range(num_classes):
        class_indices = np.where(targets == c)[0]
        if len(class_indices) < 20:
            continue

        c_features = features[class_indices]

        # Reduce dimensionality with PCA
        n_comp = min(pca_components, len(class_indices) - 1, c_features.shape[1])
        pca = PCA(n_components=n_comp, random_state=seed)
        c_reduced = pca.fit_transform(c_features)

        # 2-Means clustering
        kmeans = KMeans(n_clusters=2, random_state=seed, n_init=10)
        labels = kmeans.fit_predict(c_reduced)

        count0 = int(np.sum(labels == 0))
        count1 = int(np.sum(labels == 1))

        if count0 == 0 or count1 == 0:
            cluster_info[c] = {"flagged": False, "reason": "single_cluster"}
            continue

        # Evaluate silhouette score
        sil_score = float(silhouette_score(c_reduced, labels))

        # Identify minority cluster
        if count0 < count1:
            minority_cluster = 0
            minority_count = count0
        else:
            minority_cluster = 1
            minority_count = count1

        minority_ratio = minority_count / len(class_indices)

        # Class is flagged as poisoned if cluster separation is strong and minority cluster is small
        # (poisoned backdoors form a tight distinct minority cluster in the target class)
        is_poisoned_class = (sil_score >= silhouette_threshold) and (minority_ratio <= max_poison_cluster_ratio)

        cluster_info[c] = {
            "flagged": is_poisoned_class,
            "silhouette_score": sil_score,
            "count0": count0,
            "count1": count1,
            "minority_ratio": minority_ratio,
            "minority_cluster": minority_cluster,
        }

        if is_poisoned_class:
            poison_sub_indices = class_indices[labels == minority_cluster]
            predicted_mask[poison_sub_indices] = True

    return predicted_mask, cluster_info
