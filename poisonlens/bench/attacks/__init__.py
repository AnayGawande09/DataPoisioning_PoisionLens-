"""Poisoning attack modules."""

from poisonlens.bench.attacks.label_flip import apply_label_flip
from poisonlens.bench.attacks.badnets import apply_badnets, add_badnets_trigger
from poisonlens.bench.attacks.blended import apply_blended, blend_image

__all__ = [
    "apply_label_flip",
    "apply_badnets",
    "add_badnets_trigger",
    "apply_blended",
    "blend_image",
]
