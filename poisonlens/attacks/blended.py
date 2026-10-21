"""Blended backdoor attack implementation with low-opacity noise/pattern blending."""

from typing import Tuple, Callable
import numpy as np
from poisonlens.data.cifar import CIFAR10Subset


def create_blended_pattern(pattern_seed: int = 999) -> np.ndarray:
    """Generate a fixed static trigger pattern for blending."""
    rng = np.random.RandomState(pattern_seed)
    # Random pattern with spatial structure (repeating 4x4 blocks or smooth noise)
    base = rng.randint(0, 256, size=(8, 8, 3), dtype=np.uint8)
    pattern = np.repeat(np.repeat(base, 4, axis=0), 4, axis=1)
    return pattern


def blend_image(image: np.ndarray, pattern: np.ndarray, alpha: float = 0.20) -> np.ndarray:
    """Blend a static pattern into an image with opacity alpha."""
    blended = (1.0 - alpha) * image.astype(np.float32) + alpha * pattern.astype(np.float32)
    return np.clip(blended, 0, 255).astype(np.uint8)


def apply_blended(
    dataset: CIFAR10Subset,
    poison_rate: float = 0.05,
    target_class: int = 0,
    alpha: float = 0.20,
    seed: int = 42,
) -> Tuple[CIFAR10Subset, np.ndarray, Callable[[np.ndarray], np.ndarray]]:
    """
    Inject blended backdoor trigger into training dataset.
    Returns:
        poisoned_dataset: CIFAR10Subset with blended pattern and relabeled targets.
        poison_mask: Boolean array indicating which samples were poisoned.
        trigger_fn: Function to apply the blend trigger to test images for ASR evaluation.
    """
    rng = np.random.RandomState(seed)
    total_samples = len(dataset)
    num_to_poison = int(total_samples * poison_rate)

    pattern = create_blended_pattern(pattern_seed=999)

    images = dataset.images.copy()
    targets = dataset.targets.copy()
    is_poison = dataset.is_poison.copy()

    # Candidates are samples not already belonging to target class
    candidates = np.where(targets != target_class)[0]
    chosen_indices = rng.choice(candidates, size=num_to_poison, replace=False)

    for idx in chosen_indices:
        images[idx] = blend_image(images[idx], pattern=pattern, alpha=alpha)
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
            return blend_image(imgs, pattern=pattern, alpha=alpha)
        out = imgs.copy()
        for i in range(len(out)):
            out[i] = blend_image(out[i], pattern=pattern, alpha=alpha)
        return out

    return poisoned_dataset, is_poison, trigger_fn
