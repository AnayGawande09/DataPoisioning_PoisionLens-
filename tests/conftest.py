"""Shared synthetic fixtures. Tests never download datasets."""

import numpy as np
import torch
from torch.utils.data import DataLoader

from poisonlens.data.image_dataset import ImageArrayDataset


def synthetic_images(n: int, seed: int, num_classes: int = 10, size: int = 32) -> tuple[np.ndarray, np.ndarray]:
    """Class-dependent uint8 images (learnable signal plus noise) and balanced labels."""
    rng = np.random.RandomState(seed)
    labels = np.arange(n) % num_classes
    rng.shuffle(labels)
    base = rng.randint(0, 256, size=(num_classes, size, size, 3)).astype(np.float32)
    noise = rng.normal(0, 40, size=(n, size, size, 3))
    images = np.clip(base[labels] * 0.6 + 50 + noise, 0, 255).astype(np.uint8)
    return images, labels.astype(np.int64)


def synthetic_loaders(
    train_size: int, test_size: int, seed: int, batch_size: int = 64
) -> tuple[DataLoader, DataLoader, ImageArrayDataset, ImageArrayDataset]:
    """Deterministic train/test loaders over synthetic images (mirrors the v1 CIFAR loader API)."""
    x_tr, y_tr = synthetic_images(train_size, seed)
    x_te, y_te = synthetic_images(test_size, seed + 1000)
    train = ImageArrayDataset(x_tr, y_tr, range(train_size))
    test = ImageArrayDataset(x_te, y_te, range(test_size))
    g = torch.Generator()
    g.manual_seed(seed)
    train_loader = DataLoader(train, batch_size=batch_size, shuffle=True, generator=g, num_workers=0)
    test_loader = DataLoader(test, batch_size=batch_size, shuffle=False, num_workers=0)
    return train_loader, test_loader, train, test
