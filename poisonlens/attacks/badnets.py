"""BadNets backdoor attack implementation with localized pixel patch trigger."""

from typing import Tuple, Callable
import numpy as np
import torch
from poisonlens.data.cifar import CIFAR10Subset


def add_badnets_trigger(
    image: np.ndarray,
    patch_size: int = 3,
    location: str = "bottom_right",
) -> np.ndarray:
    """
    Stamp a distinct high-contrast patch onto a 32x32x3 uint8 image.
    Location 'bottom_right': rows [32-patch_size-1 : 32-1], cols [32-patch_size-1 : 32-1]
    """
    img = image.copy()
    h, w, c = img.shape
    r_start = h - patch_size - 1
    r_end = h - 1
    c_start = w - patch_size - 1
    c_end = w - 1

    # Bright yellow/white high-contrast patch
    img[r_start:r_end, c_start:c_end, :] = 255
    return img


def apply_badnets(
    dataset: CIFAR10Subset,
    poison_rate: float = 0.05,
    target_class: int = 0,
    patch_size: int = 3,
    seed: int = 42,
) -> Tuple[CIFAR10Subset, np.ndarray, Callable[[np.ndarray], np.ndarray]]:
    """
    Inject BadNets backdoor trigger into training dataset.
    Returns:
        poisoned_dataset: CIFAR10Subset with trigger stamped and targets set to target_class.
        poison_mask: Boolean array indicating which samples were poisoned.
        trigger_fn: Function to apply the trigger to test images for ASR evaluation.
    """
    rng = np.random.RandomState(seed)
    total_samples = len(dataset)
    num_to_poison = int(total_samples * poison_rate)

    images = dataset.images.copy()
    targets = dataset.targets.copy()
    is_poison = dataset.is_poison.copy()

    # Candidate indices are samples NOT already belonging to the target class
    candidates = np.where(targets != target_class)[0]
    chosen_indices = rng.choice(candidates, size=num_to_poison, replace=False)

    for idx in chosen_indices:
        images[idx] = add_badnets_trigger(images[idx], patch_size=patch_size)
        targets[idx] = target_class
        is_poison[idx] = True

    poisoned_dataset = CIFAR10Subset(
        images=images,
        targets=targets,
        sample_ids=dataset.sample_ids,
        cifar_indices=dataset.cifar_indices,
        is_poison=is_poison,
    )

    def trigger_fn(imgs: np.ndarray) -> np.ndarray:
        if imgs.ndim == 3:
            return add_badnets_trigger(imgs, patch_size=patch_size)
        out = imgs.copy()
        for i in range(len(out)):
            out[i] = add_badnets_trigger(out[i], patch_size=patch_size)
        return out

    return poisoned_dataset, is_poison, trigger_fn
