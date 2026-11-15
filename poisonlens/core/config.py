"""Scan configuration: every threshold used by the pipeline, in one validated place.

``ScanConfig()`` equals the *Standard* profile. ``configs/scan_{quick,default,deep}.yaml``
override it per profile; :func:`load_scan_config` merges a profile file plus optional
overrides and validates the result. Unknown keys anywhere are errors.

Field descriptions starting with ``spec:`` are values fixed by ``POISONLENS_V2_SPEC.md``.
``provisional:`` marks values the spec leaves open; they are starting points that the
Phase 12 benchmark must validate (never tuned on test fixtures). See docs/CONFIG.md.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from poisonlens.core.errors import ConfigError

KiB = 1024
MiB = 1024 * KiB
GiB = 1024 * MiB

ProfileName = Literal["quick", "standard", "deep"]

PROFILE_FILES: dict[str, str] = {
    "quick": "scan_quick.yaml",
    "standard": "scan_default.yaml",
    "deep": "scan_deep.yaml",
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


# --------------------------------------------------------------------------- S0 limits


class UploadLimits(_Strict):
    max_upload_bytes: int = Field(2 * GiB, gt=0, description="spec: default max upload 2 GB")
    part_size_bytes: int = Field(8 * MiB, gt=0, description="spec: browser sends 8 MB parts")
    disk_quota_bytes: int = Field(50 * GiB, gt=0, description="provisional: total bytes under data/scans")
    uploads_per_minute_per_ip: int = Field(30, gt=0, description="provisional: per-IP upload rate limit")
    max_filename_length: int = Field(255, gt=0, description="provisional: F04 over-long name threshold")

    @model_validator(mode="after")
    def _part_fits(self) -> UploadLimits:
        if self.part_size_bytes > self.max_upload_bytes:
            raise ValueError("part_size_bytes cannot exceed max_upload_bytes")
        return self


class ArchiveLimits(_Strict):
    max_compression_ratio: float = Field(100.0, gt=1.0, description="spec: F02 ratio > 100:1")
    max_nesting_depth: int = Field(3, ge=0, description="spec: F02 nesting > 3")
    max_entries: int = Field(200_000, gt=0, description="provisional: F02 entry-count cap")
    max_entry_bytes: int = Field(2 * GiB, gt=0, description="provisional: per-entry uncompressed cap")
    max_total_bytes: int = Field(20 * GiB, gt=0, description="provisional: total uncompressed cap")

    @model_validator(mode="after")
    def _entry_le_total(self) -> ArchiveLimits:
        if self.max_entry_bytes > self.max_total_bytes:
            raise ValueError("max_entry_bytes cannot exceed max_total_bytes")
        return self


class WorkerLimits(_Strict):
    """Limits for the isolated parse/scan child process."""

    max_memory_bytes: int = Field(4 * GiB, gt=0, description="provisional: RSS cap, watchdog kills above")
    wall_clock_seconds: float = Field(1800.0, gt=0, description="provisional: per parse job")
    cpu_seconds: float = Field(1800.0, gt=0, description="provisional: per parse job")
    poll_interval_seconds: float = Field(0.25, gt=0, description="provisional: watchdog sampling period")


class ParseLimits(_Strict):
    max_image_pixels: int = Field(50_000_000, gt=0, description="provisional: F12 decompression-bomb pixel cap")
    reject_svg: bool = Field(True, description="spec: SVG rejected by default")
    json_max_depth: int = Field(6, gt=0, description="provisional: JSON flatten depth cap")
    json_max_keys: int = Field(2_000, gt=0, description="provisional: JSON key-explosion cap")
    inspect_sample_rows: int = Field(10_000, gt=0, description="provisional: rows sampled for profiling")
    ram_budget_bytes: int = Field(2 * GiB, gt=0, description="provisional: chunk sizing for streaming reads")


class Limits(_Strict):
    upload: UploadLimits = Field(default_factory=UploadLimits)
    archive: ArchiveLimits = Field(default_factory=ArchiveLimits)
    worker: WorkerLimits = Field(default_factory=WorkerLimits)
    parse: ParseLimits = Field(default_factory=ParseLimits)


# --------------------------------------------------------------------------- S2 security


class SecurityConfig(_Strict):
    halt_on_critical_file: bool = Field(True, description="spec: critical file-level findings halt parsing")
    halting_checks: list[str] = Field(
        default_factory=lambda: ["F03", "F06", "F07"], description="spec (build plan): checks that may halt"
    )
    check_timeout_seconds: float = Field(60.0, gt=0, description="provisional: per-check timeout")
    url_column_fraction: float = Field(0.80, gt=0, le=1, description="spec (build plan): F14 >= 80% URLs")
    base64_min_length: int = Field(256, gt=0, description="provisional: C03 base64 blob length")
    text_sample_rows: int = Field(50_000, gt=0, description="provisional: C01-C05 bounded text sample")
    network_access: bool = Field(False, description="spec: network off by default; no URL is fetched")
    use_clamav: bool = Field(True, description="spec: F06 uses ClamAV if installed (auto-detected)")
    use_yara: bool = Field(True, description="spec: F06 uses YARA if installed (auto-detected)")


# --------------------------------------------------------------------------- S3 quality


class QualityConfig(_Strict):
    trigger_min_support_abs: int = Field(10, gt=0, description="spec (build plan): support >= max(10, 0.1% N)")
    trigger_min_support_frac: float = Field(0.001, gt=0, lt=1, description="spec (build plan)")
    trigger_min_purity: float = Field(0.98, gt=0, le=1, description="spec (build plan): purity >= 0.98")
    trigger_max_outside_df: float = Field(0.01, ge=0, lt=1, description="provisional: doc-freq outside class")
    trigger_top_k: int = Field(20, gt=0, description="provisional: candidates kept in trigger_candidates.json")
    phash_hamming_radius: int = Field(4, ge=0, description="provisional: image near-duplicate radius")
    minhash_num_perm: int = Field(128, gt=0, description="provisional")
    minhash_lsh_threshold: float = Field(0.85, gt=0, le=1, description="provisional: text near-dup Jaccard")
    tabular_round_decimals: int = Field(6, ge=0, description="provisional: rounding before row hashing")
    tiny_class_min_support: int = Field(5, gt=0, description="provisional: C08 tiny-class flag")
    imbalance_ratio_warn: float = Field(20.0, gt=1, description="provisional: C08 majority/minority ratio")
    fuzzy_label_score: float = Field(90.0, gt=0, le=100, description="provisional: rapidfuzz merge candidate")
    outlier_mad_z: float = Field(3.5, gt=0, description="provisional: C10 robust-z threshold")
    shortcut_single_feature_accuracy: float = Field(0.98, gt=0, le=1, description="provisional: C10")


# --------------------------------------------------------------------------- S4 features + probe


class FeatureConfig(_Strict):
    text_ngram_max: int = Field(2, ge=1, description="spec: TF-IDF 1-2 grams")
    text_svd_dims: int = Field(256, gt=0, description="spec: TruncatedSVD 256-d")
    tabular_onehot_max_cardinality: int = Field(50, gt=1, description="provisional: above this, hashing")
    tabular_hash_dims: int = Field(256, gt=0, description="provisional: hashing-trick width")
    audio_n_mels: int = Field(64, gt=0, description="spec: log-mel 64 bins")
    audio_sample_rate: int = Field(16_000, gt=0, description="provisional")
    audio_crop_seconds: float = Field(1.0, gt=0, description="provisional: fixed crop")
    image_frozen_min_images: int = Field(50_000, gt=0, description="spec: frozen mode default for > 50k images")


class ProbeConfig(_Strict):
    epochs: int = Field(10, ge=2, description="spec: Quick 6 / Standard 10 / Deep 16")
    seeds: list[int] = Field(default_factory=lambda: [0, 1, 2], min_length=1, description="spec: 1 / 3 / 3 seeds")
    image_resolution: int = Field(32, gt=0, description="spec: 32 / 32 / 64")
    n_chunks: int = Field(4, ge=2, description="spec: K = 4 stratified chunks")
    chunks_trained_per_epoch: int = Field(2, ge=1, description="spec: 2 of 4 chunks trained per epoch")
    kmeans_max_clusters: int = Field(32, gt=0, description="spec (build plan): min(32, N/200)")
    kmeans_samples_per_cluster: int = Field(200, gt=0, description="spec (build plan): min(32, N/200)")
    min_epochs: int = Field(4, ge=1, description="provisional: no early stop before this epoch")
    early_stop_spearman: float = Field(0.98, gt=0, le=1, description="spec: Spearman > 0.98")
    early_stop_patience: int = Field(2, ge=1, description="spec: for 2 consecutive epochs")
    el2n_epochs: list[int] = Field(default_factory=lambda: [2, 3], min_length=1, description="spec: epochs 2-3")
    ssn_start_epoch: int = Field(3, ge=1, description="spec: after epoch 3")
    ssn_top_fraction: float = Field(0.30, gt=0, le=1, description="spec: top ~30% tracked densely")
    knn_k: int = Field(15, gt=0, description="spec: k = 15")
    sketch_threshold: int = Field(200_000, gt=0, description="spec: sketch + propagate above 200k records")
    train_batch_size: int = Field(128, gt=0, description="provisional")
    score_batch_size: int = Field(1024, gt=0, description="provisional: forward-only scoring batch")
    learning_rate: float = Field(3e-3, gt=0, description="provisional: one-cycle max LR (AdamW)")
    weight_decay: float = Field(1e-4, ge=0, description="provisional")
    time_budget_seconds: float = Field(900.0, gt=0, description="provisional: profile time box")
    tiny_dataset_min_records: int = Field(200, gt=0, description="provisional: below this fall back to K=2")

    @model_validator(mode="after")
    def _consistent(self) -> ProbeConfig:
        if self.chunks_trained_per_epoch >= self.n_chunks:
            raise ValueError("chunks_trained_per_epoch must be < n_chunks (otherwise nothing is held out)")
        if self.min_epochs > self.epochs:
            raise ValueError("min_epochs cannot exceed epochs")
        if max(self.el2n_epochs) > self.epochs or min(self.el2n_epochs) < 1:
            raise ValueError("el2n_epochs must lie within 1..epochs")
        if self.ssn_start_epoch > self.epochs:
            raise ValueError("ssn_start_epoch cannot exceed epochs")
        if len(set(self.seeds)) != len(self.seeds):
            raise ValueError("seeds must be unique")
        return self


# --------------------------------------------------------------------------- S5 detect + risk


FamilyName = Literal["trajectory", "heldout", "representation"]
RiskComponent = Literal["contamination", "agreement", "label_noise_excess", "trigger_strength", "security_severity"]


def _default_family_weights() -> dict[FamilyName, float]:
    return {"trajectory": 0.8, "heldout": 0.8, "representation": 0.8}


def _default_risk_weights() -> dict[RiskComponent, float]:
    return {
        "contamination": 0.35,
        "agreement": 0.20,
        "label_noise_excess": 0.15,
        "trigger_strength": 0.15,
        "security_severity": 0.15,
    }


class DetectConfig(_Strict):
    family_weights: dict[FamilyName, float] = Field(
        default_factory=_default_family_weights,
        description="provisional: noisy-OR w_f, equal until Phase 12 validation",
    )
    vote_threshold: float = Field(0.5, gt=0, lt=1, description="provisional: family score counted as a vote")
    contamination_min: float = Field(0.005, gt=0, lt=1, description="spec: eps-hat clipped to [0.5%, 15%]")
    contamination_max: float = Field(0.15, gt=0, lt=1, description="spec: eps-hat clipped to [0.5%, 15%]")
    bootstrap_samples: int = Field(200, gt=0, description="provisional: eps-hat confidence range")
    reasons_top_signals: int = Field(3, gt=0, description="provisional: signals quoted per explanation")

    @model_validator(mode="after")
    def _ranges(self) -> DetectConfig:
        if set(self.family_weights) != {"trajectory", "heldout", "representation"}:
            raise ValueError("family_weights must define trajectory, heldout and representation")
        if any(not 0.0 <= w <= 1.0 for w in self.family_weights.values()):
            raise ValueError("family weights must be in [0, 1] for noisy-OR")
        if self.contamination_min >= self.contamination_max:
            raise ValueError("contamination_min must be < contamination_max")
        return self


class RiskConfig(_Strict):
    weights: dict[RiskComponent, float] = Field(
        default_factory=_default_risk_weights,
        description="provisional: Poison Risk Score blend (must sum to 1)",
    )
    suspicious_threshold: float = Field(30.0, ge=0, le=100, description="provisional: score >= -> Suspicious")
    likely_poisoned_threshold: float = Field(60.0, ge=0, le=100, description="provisional: -> Likely Poisoned")

    @model_validator(mode="after")
    def _valid(self) -> RiskConfig:
        if len(self.weights) != 5:
            raise ValueError("risk weights must define all five components")
        if any(w < 0 for w in self.weights.values()) or abs(sum(self.weights.values()) - 1.0) > 1e-6:
            raise ValueError("risk weights must be non-negative and sum to 1")
        if self.suspicious_threshold >= self.likely_poisoned_threshold:
            raise ValueError("suspicious_threshold must be < likely_poisoned_threshold")
        return self


# --------------------------------------------------------------------------- S6 sanitize


class TierConfig(_Strict):
    tier3_max_fraction: float = Field(0.10, gt=0, lt=1, description="spec: Tier 3 = top min(eps, 10%)")
    tier3_min_votes: int = Field(2, ge=1, description="spec: and >= 2 family votes ...")
    tier3_extreme_z: float = Field(6.0, gt=0, description="spec: ... or extreme single-detector z > 6")
    tier2_multiplier: float = Field(2.0, gt=0, description="spec: Tier 2 = next min(2*eps, 15%)")
    tier2_max_fraction: float = Field(0.15, gt=0, lt=1, description="spec: Tier 2 cap 15%")
    keep_weight: float = Field(1.0, ge=0, le=1, description="spec: Tier 1 weight")
    downweight_weight: float = Field(0.20, ge=0, le=1, description="spec: Tier 2 weight")
    quarantine_weight: float = Field(0.0, ge=0, le=1, description="spec: Tier 3 weight")


class CanaryConfig(_Strict):
    max_size: int = Field(500, gt=0, description="spec: canary = min(500, 5% of labeled)")
    fraction: float = Field(0.05, gt=0, lt=1, description="spec: canary = min(500, 5% of labeled)")
    min_per_class: int = Field(20, gt=0, description="spec: >= 20 per class where possible")
    max_accuracy_drop_pts: float = Field(3.0, gt=0, description="spec: breach if accuracy drops > 3.0 pts")
    max_class_drop_pts: float = Field(10.0, gt=0, description="spec: breach if any class drops > 10 pts")
    max_retries: int = Field(3, ge=0, description="spec: retry up to 3 times")
    relax_factor: float = Field(0.5, gt=0, lt=1, description="spec: halve Tier 3 / Tier 2 budgets")


class ExportConfig(_Strict):
    neutralize_formulas: bool = Field(False, description="spec: optional F10 formula neutralization")
    strip_image_metadata: bool = Field(False, description="spec: optional image metadata stripping")


# --------------------------------------------------------------------------- root


class ScanConfig(_Strict):
    profile: ProfileName = Field("standard", description="spec: Quick / Standard (default) / Deep")
    seed: int = Field(42, description="provisional: base seed for everything not covered by probe.seeds")
    limits: Limits = Field(default_factory=Limits)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    quality: QualityConfig = Field(default_factory=QualityConfig)
    features: FeatureConfig = Field(default_factory=FeatureConfig)
    probe: ProbeConfig = Field(default_factory=ProbeConfig)
    detect: DetectConfig = Field(default_factory=DetectConfig)
    risk: RiskConfig = Field(default_factory=RiskConfig)
    tiers: TierConfig = Field(default_factory=TierConfig)
    canary: CanaryConfig = Field(default_factory=CanaryConfig)
    export: ExportConfig = Field(default_factory=ExportConfig)


# --------------------------------------------------------------------------- loading


def default_config_dir() -> Path:
    """``$POISONLENS_CONFIG_DIR`` if set, else ``<repo>/configs``."""
    env = os.environ.get("POISONLENS_CONFIG_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[2] / "configs"


def _deep_merge(base: dict[str, Any], override: Mapping[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in override.items():
        if isinstance(value, Mapping) and isinstance(out.get(key), Mapping):
            out[key] = _deep_merge(dict(out[key]), value)
        else:
            out[key] = value
    return out


def _read_yaml(path: Path) -> dict[str, Any]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config file not found: {path}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {path.name}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name}: top level must be a mapping")
    return data


def load_scan_config(
    profile: str = "standard",
    overrides: Mapping[str, Any] | None = None,
    config_dir: Path | None = None,
) -> ScanConfig:
    """Build a validated :class:`ScanConfig` from a profile YAML plus optional nested overrides.

    Raises :class:`ConfigError` for an unknown profile, bad YAML, unknown keys or invalid values.
    """
    if profile not in PROFILE_FILES:
        raise ConfigError(f"unknown profile {profile!r}; expected one of {sorted(PROFILE_FILES)}")
    path = (config_dir or default_config_dir()) / PROFILE_FILES[profile]
    data = _read_yaml(path)
    file_profile = data.get("profile", profile)
    if file_profile != profile:
        raise ConfigError(f"{path.name} declares profile {file_profile!r}, expected {profile!r}")
    if overrides:
        data = _deep_merge(data, overrides)
        if data.get("profile", profile) != profile:
            raise ConfigError("overrides cannot change the profile; choose a different profile instead")
    data["profile"] = profile
    try:
        return ScanConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError(f"invalid scan config ({path.name}): {exc}") from exc
