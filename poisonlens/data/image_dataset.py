"""Generic in-memory image dataset with stable sample ids.

This replaces the v1 CIFAR-specific dataset class inside the product code.
Dataset-specific loaders (e.g. the CIFAR-10 benchmark loader) live in
``poisonlens.bench`` and subclass this.
"""

from __future__ import annotations

from typing import Optional, Sequence, Tuple

import numpy as np
import torch
from torch.utils.data import Dataset

DEFAULT_MEAN: Tuple[float, float, float] = (0.5, 0.5, 0.5)
DEFAULT_STD: Tuple[float, float, float] = (0.5, 0.5, 0.5)


class ImageArrayDataset(Dataset):
    """Images held as a ``(N, H, W, C)`` uint8 array plus integer targets.

    ``__getitem__`` returns ``(normalized_tensor, target, sample_id)`` so that
    training/scoring code can record per-sample dynamics by stable id.
    """

    def __init__(
        self,
        images: np.ndarray,
        targets: Sequence[int],
        sample_ids: Sequence[int],
        source_indices: Optional[Sequence[int]] = None,
        mean: Sequence[float] = DEFAULT_MEAN,
        std: Sequence[float] = DEFAULT_STD,
    ):
        if source_indices is None:
            source_indices = range(len(images))
        if not (len(images) == len(targets) == len(sample_ids) == len(source_indices)):
            raise ValueError("images, targets, sample_ids and source_indices must have equal length")
        self.images = np.array(images, copy=True)
        self.targets = np.array(targets, dtype=np.int64, copy=True)
        self.sample_ids = np.array(sample_ids, dtype=np.int64, copy=True)
        self.source_indices = np.array(source_indices, dtype=np.int64, copy=True)
        self.mean = tuple(float(m) for m in mean)
        self.std = tuple(float(s) for s in std)

        channels = self.images.shape[-1]
        mean_t = torch.tensor(self.mean, dtype=torch.float32).view(1, channels, 1, 1)
        std_t = torch.tensor(self.std, dtype=torch.float32).view(1, channels, 1, 1)
        tensors = torch.from_numpy(self.images).permute(0, 3, 1, 2).float() / 255.0
        self.tensors = (tensors - mean_t) / std_t

    def __len__(self) -> int:
        return len(self.images)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, int, int]:
        return self.tensors[idx], int(self.targets[idx]), int(self.sample_ids[idx])
