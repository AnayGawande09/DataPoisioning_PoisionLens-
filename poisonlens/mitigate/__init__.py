"""Mitigation strategies: 3-tier sample weighting, soft quarantine, and canary guardrails."""

from poisonlens.mitigate.tier_scoring import (
    assign_mitigation_tiers,
    assign_hard_deletion,
    measure_wrongly_quarantined,
)
from poisonlens.mitigate.canary import CanaryGuard

__all__ = [
    "assign_mitigation_tiers",
    "assign_hard_deletion",
    "measure_wrongly_quarantined",
    "CanaryGuard",
]
