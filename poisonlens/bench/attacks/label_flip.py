"""Targeted label flipping attack implementation."""

from typing import Tuple
import numpy as np
import copy
from poisonlens.bench.datasets.cifar import CIFAR10Subset


def apply_label_flip(
    dataset: CIFAR10Subset,
    poison_rate: float,
    source_class: int = 3,  # e.g., cat
    target_class: int = 5,  # e.g., dog
    seed: int = 42,
) -> Tuple[CIFAR10Subset, np.ndarray]:
    """
    Flip labels of samples belonging to source_class to target_class.
    poison_rate specifies the fraction of TOTAL training samples to poison.
    Returns:
        poisoned_dataset: A new CIFAR10Subset with modified targets and poison flags.
        poison_mask: Boolean numpy array of length N where True indicates a poisoned sample.
    """
    rng = np.random.RandomState(seed)
    total_samples = len(dataset)
    num_to_poison = int(total_samples * poison_rate)

    targets = dataset.targets.copy()
    is_poison = dataset.is_poison.copy()

    # Find candidate indices belonging to source_class
    source_indices = np.where(targets == source_class)[0]
    if len(source_indices) < num_to_poison:
        raise ValueError(
            f"Requested {num_to_poison} poisoned samples, but source class {source_class} "
            f"only contains {len(source_indices)} samples in this dataset."
        )

    chosen_indices = rng.choice(source_indices, size=num_to_poison, replace=False)
    targets[chosen_indices] = target_class
    is_poison[chosen_indices] = True

    poisoned_dataset = CIFAR10Subset(
        images=dataset.images,
        targets=targets,
        sample_ids=dataset.sample_ids,
        cifar_indices=dataset.cifar_indices,
        is_poison=is_poison,
    )

    poison_mask = is_poison.copy()
    return poisoned_dataset, poison_mask
