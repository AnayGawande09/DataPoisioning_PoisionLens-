"""Tests for poisoning attacks."""

import numpy as np
import pytest
from poisonlens.data.cifar import load_cifar10_subsets
from poisonlens.attacks.label_flip import apply_label_flip
from poisonlens.attacks.badnets import apply_badnets, add_badnets_trigger
from poisonlens.attacks.blended import apply_blended, blend_image


@pytest.fixture
def clean_subsets():
    train_sub, test_sub, _ = load_cifar10_subsets("./data_cache", train_size=500, test_size=100, seed=42)
    return train_sub, test_sub


def test_label_flip(clean_subsets):
    train_sub, _ = clean_subsets
    source_class = 3
    target_class = 5
    poison_rate = 0.05
    expected_poisoned = int(len(train_sub) * poison_rate)

    poisoned_sub, mask = apply_label_flip(
        train_sub,
        poison_rate=poison_rate,
        source_class=source_class,
        target_class=target_class,
        seed=42,
    )

    assert mask.sum() == expected_poisoned
    assert (poisoned_sub.targets[mask] == target_class).all()
    # Non-poisoned samples retain identical targets
    assert (poisoned_sub.targets[~mask] == train_sub.targets[~mask]).all()
    # Images should not be modified in label flip
    assert np.array_equal(poisoned_sub.images, train_sub.images)


def test_badnets(clean_subsets):
    train_sub, _ = clean_subsets
    target_class = 0
    poison_rate = 0.05
    expected_poisoned = int(len(train_sub) * poison_rate)

    poisoned_sub, mask, trigger_fn = apply_badnets(
        train_sub,
        poison_rate=poison_rate,
        target_class=target_class,
        patch_size=3,
        seed=42,
    )

    assert mask.sum() == expected_poisoned
    assert (poisoned_sub.targets[mask] == target_class).all()
    # Check that poisoned images have the patch stamped
    for idx in np.where(mask)[0]:
        img = poisoned_sub.images[idx]
        assert (img[28:31, 28:31, :] == 255).all()

    # Test trigger_fn on clean images
    clean_sample = train_sub.images[0]
    stamped = trigger_fn(clean_sample)
    assert (stamped[28:31, 28:31, :] == 255).all()


def test_blended(clean_subsets):
    train_sub, _ = clean_subsets
    target_class = 0
    poison_rate = 0.05
    expected_poisoned = int(len(train_sub) * poison_rate)

    poisoned_sub, mask, trigger_fn = apply_blended(
        train_sub,
        poison_rate=poison_rate,
        target_class=target_class,
        alpha=0.20,
        seed=42,
    )

    assert mask.sum() == expected_poisoned
    assert (poisoned_sub.targets[mask] == target_class).all()

    # Images should be modified for poisoned samples
    diff = np.abs(poisoned_sub.images[mask].astype(float) - train_sub.images[mask].astype(float))
    assert diff.max() > 0

    # Unpoisoned images must remain untouched
    assert np.array_equal(poisoned_sub.images[~mask], train_sub.images[~mask])
