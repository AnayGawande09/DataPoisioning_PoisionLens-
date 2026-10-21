"""CIFAR-10 data loader with deterministic subsetting, stable sample IDs, and git-style provenance hashing."""

import os
from typing import Tuple, List, Optional, Sequence
import numpy as np
import torch
from torch.utils.data import Dataset, DataLoader
import torchvision

from poisonlens.utils import set_seed, compute_indices_hash


CIFAR10_MEAN = (0.4914, 0.4822, 0.4465)
CIFAR10_STD = (0.2470, 0.2435, 0.2616)


class CIFAR10Subset(Dataset):
    """PyTorch Dataset wrapper providing stable sample_id, clean/poison masks, and provenance."""

    def __init__(
        self,
        images: np.ndarray,
        targets: Sequence[int],
        sample_ids: Sequence[int],
        cifar_indices: Sequence[int],
        is_poison: Optional[np.ndarray] = None,
    ):
        assert len(images) == len(targets) == len(sample_ids) == len(cifar_indices)
        self.images = np.array(images, copy=True)  # Shape: (N, 32, 32, 3), uint8
        self.targets = np.array(targets, dtype=np.int64, copy=True)
        self.sample_ids = np.array(sample_ids, dtype=np.int64, copy=True)
        self.cifar_indices = np.array(cifar_indices, dtype=np.int64, copy=True)
        if is_poison is None:
            self.is_poison = np.zeros(len(images), dtype=bool)
        else:
            self.is_poison = np.array(is_poison, dtype=bool, copy=True)

        # Pre-compute normalized tensor array for maximum CPU throughput (avoids per-sample PIL overhead)
        mean = torch.tensor(CIFAR10_MEAN, dtype=torch.float32).view(1, 3, 1, 1)
        std = torch.tensor(CIFAR10_STD, dtype=torch.float32).view(1, 3, 1, 1)
        tensors = torch.from_numpy(self.images).permute(0, 3, 1, 2).float() / 255.0
        self.tensors = (tensors - mean) / std

    def __len__(self) -> int:
        return len(self.images)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, int, int]:
        return self.tensors[idx], int(self.targets[idx]), int(self.sample_ids[idx])

    def get_sample(self, sample_id: int) -> Tuple[np.ndarray, int, bool, int]:
        """Fetch raw image (uint8), target, poison status, and original cifar index by stable sample_id."""
        idx = int(sample_id)
        return self.images[idx], int(self.targets[idx]), bool(self.is_poison[idx]), int(self.cifar_indices[idx])


def get_stratified_indices(
    targets: Sequence[int],
    total_samples: int,
    num_classes: int = 10,
    seed: int = 42,
) -> np.ndarray:
    """Select a balanced, deterministic subset of indices across classes."""
    rng = np.random.RandomState(seed)
    targets_arr = np.array(targets)
    per_class = total_samples // num_classes
    selected_indices: List[int] = []

    for c in range(num_classes):
        class_indices = np.where(targets_arr == c)[0]
        chosen = rng.choice(class_indices, size=per_class, replace=False)
        selected_indices.extend(chosen.tolist())

    selected_indices.sort()
    return np.array(selected_indices, dtype=np.int64)


def load_cifar10_subsets(
    data_root: str = "./data_cache",
    train_size: int = 10000,
    test_size: int = 2000,
    seed: int = 42,
) -> Tuple[CIFAR10Subset, CIFAR10Subset, str]:
    """Load CIFAR-10, extract fixed stratified subsets, assign sample IDs, and compute git-style hash."""
    set_seed(seed)

    # Load full torchvision CIFAR-10 datasets
    train_raw = torchvision.datasets.CIFAR10(root=data_root, train=True, download=False)
    test_raw = torchvision.datasets.CIFAR10(root=data_root, train=False, download=False)

    # Deterministic stratified splits
    train_indices = get_stratified_indices(train_raw.targets, train_size, num_classes=10, seed=seed)
    test_indices = get_stratified_indices(test_raw.targets, test_size, num_classes=10, seed=seed + 1000)

    # Compute provenance git-style hash of the training subset indices
    data_hash = compute_indices_hash(train_indices)

    # Build subsets with pre-vectorized tensor caches
    train_subset = CIFAR10Subset(
        images=train_raw.data[train_indices],
        targets=[train_raw.targets[i] for i in train_indices],
        sample_ids=list(range(len(train_indices))),
        cifar_indices=train_indices,
    )

    test_subset = CIFAR10Subset(
        images=test_raw.data[test_indices],
        targets=[test_raw.targets[i] for i in test_indices],
        sample_ids=list(range(len(test_indices))),
        cifar_indices=test_indices,
    )

    return train_subset, test_subset, data_hash


def get_cifar10_loaders(
    data_root: str = "./data_cache",
    train_size: int = 10000,
    test_size: int = 2000,
    batch_size: int = 128,
    seed: int = 42,
    num_workers: int = 0,
) -> Tuple[DataLoader, DataLoader, CIFAR10Subset, CIFAR10Subset, str]:
    """Create deterministic DataLoaders for train and test subsets."""
    train_subset, test_subset, data_hash = load_cifar10_subsets(
        data_root=data_root,
        train_size=train_size,
        test_size=test_size,
        seed=seed,
    )

    # Deterministic loader generator
    g = torch.Generator()
    g.manual_seed(seed)

    train_loader = DataLoader(
        train_subset,
        batch_size=batch_size,
        shuffle=True,
        generator=g,
        num_workers=num_workers,
        pin_memory=False,
    )

    test_loader = DataLoader(
        test_subset,
        batch_size=batch_size,
        shuffle=False,
        num_workers=num_workers,
        pin_memory=False,
    )

    return train_loader, test_loader, train_subset, test_subset, data_hash
