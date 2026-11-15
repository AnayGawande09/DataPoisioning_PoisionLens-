"""ScanConfig defaults must equal the spec; profile files must match spec section 4.2."""

from pathlib import Path

import pytest

from poisonlens.core.config import GiB, MiB, ScanConfig, load_scan_config
from poisonlens.core.errors import ConfigError

# (dotted path, spec value) — every value fixed by POISONLENS_V2_SPEC.md / the build plan.
SPEC_DEFAULTS = [
    ("limits.upload.max_upload_bytes", 2 * GiB),
    ("limits.upload.part_size_bytes", 8 * MiB),
    ("limits.archive.max_compression_ratio", 100.0),
    ("limits.archive.max_nesting_depth", 3),
    ("limits.parse.reject_svg", True),
    ("security.halt_on_critical_file", True),
    ("security.halting_checks", ["F03", "F06", "F07"]),
    ("security.url_column_fraction", 0.80),
    ("security.network_access", False),
    ("quality.trigger_min_support_abs", 10),
    ("quality.trigger_min_support_frac", 0.001),
    ("quality.trigger_min_purity", 0.98),
    ("features.text_ngram_max", 2),
    ("features.text_svd_dims", 256),
    ("features.audio_n_mels", 64),
    ("features.image_frozen_min_images", 50_000),
    ("probe.epochs", 10),
    ("probe.seeds", [0, 1, 2]),
    ("probe.image_resolution", 32),
    ("probe.n_chunks", 4),
    ("probe.chunks_trained_per_epoch", 2),
    ("probe.kmeans_max_clusters", 32),
    ("probe.kmeans_samples_per_cluster", 200),
    ("probe.early_stop_spearman", 0.98),
    ("probe.early_stop_patience", 2),
    ("probe.el2n_epochs", [2, 3]),
    ("probe.ssn_start_epoch", 3),
    ("probe.ssn_top_fraction", 0.30),
    ("probe.knn_k", 15),
    ("probe.sketch_threshold", 200_000),
    ("detect.contamination_min", 0.005),
    ("detect.contamination_max", 0.15),
    ("tiers.tier3_max_fraction", 0.10),
    ("tiers.tier3_min_votes", 2),
    ("tiers.tier3_extreme_z", 6.0),
    ("tiers.tier2_multiplier", 2.0),
    ("tiers.tier2_max_fraction", 0.15),
    ("tiers.keep_weight", 1.0),
    ("tiers.downweight_weight", 0.20),
    ("tiers.quarantine_weight", 0.0),
    ("canary.max_size", 500),
    ("canary.fraction", 0.05),
    ("canary.min_per_class", 20),
    ("canary.max_accuracy_drop_pts", 3.0),
    ("canary.max_class_drop_pts", 10.0),
    ("canary.max_retries", 3),
    ("canary.relax_factor", 0.5),
]


def _get(cfg, dotted):
    obj = cfg
    for part in dotted.split("."):
        obj = getattr(obj, part)
    return obj


@pytest.mark.parametrize("dotted,expected", SPEC_DEFAULTS, ids=[d for d, _ in SPEC_DEFAULTS])
def test_defaults_match_spec(dotted, expected):
    assert _get(ScanConfig(), dotted) == expected


def test_tier_weights_match_enum():
    from poisonlens.core.schemas import Tier

    t = ScanConfig().tiers
    assert (t.keep_weight, t.downweight_weight, t.quarantine_weight) == (
        Tier.KEEP.weight,
        Tier.DOWNWEIGHT.weight,
        Tier.QUARANTINE.weight,
    )


def test_risk_weights_sum_to_one():
    assert sum(ScanConfig().risk.weights.values()) == pytest.approx(1.0)


@pytest.mark.parametrize(
    "profile,epochs,n_seeds,res",
    [("quick", 6, 1, 32), ("standard", 10, 3, 32), ("deep", 16, 3, 64)],
)
def test_profile_files_match_spec_table(profile, epochs, n_seeds, res):
    cfg = load_scan_config(profile)
    assert cfg.profile == profile
    assert cfg.probe.epochs == epochs
    assert len(cfg.probe.seeds) == n_seeds
    assert cfg.probe.image_resolution == res


@pytest.mark.parametrize("profile", ["quick", "standard", "deep"])
def test_profile_rotation_is_exact(profile):
    """Spec: each chunk is trained in exactly E * trained / K epochs; default profiles divide evenly."""
    p = load_scan_config(profile).probe
    assert (p.epochs * p.chunks_trained_per_epoch) % p.n_chunks == 0


def test_default_yaml_equals_constructor_defaults():
    assert load_scan_config("standard") == ScanConfig()


def test_overrides_merge_nested():
    cfg = load_scan_config("standard", overrides={"probe": {"knn_k": 7}, "canary": {"max_retries": 1}})
    assert cfg.probe.knn_k == 7
    assert cfg.probe.epochs == 10  # untouched sibling keeps the profile value
    assert cfg.canary.max_retries == 1


@pytest.mark.parametrize(
    "overrides",
    [
        {"no_such_key": 1},
        {"probe": {"epocs": 3}},
        {"limits": {"archive": {"max_ratio": 5}}},
    ],
)
def test_unknown_keys_are_errors(overrides):
    with pytest.raises(ConfigError):
        load_scan_config("standard", overrides=overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"probe": {"chunks_trained_per_epoch": 4}},  # nothing held out
        {"probe": {"seeds": [1, 1]}},
        {"probe": {"epochs": 3, "min_epochs": 4}},
        {"detect": {"family_weights": {"trajectory": 1.5, "heldout": 0.5, "representation": 0.5}}},
        {"detect": {"contamination_min": 0.2}},
        {
            "risk": {
                "weights": {
                    "contamination": 1.0,
                    "agreement": 1.0,
                    "label_noise_excess": 0.0,
                    "trigger_strength": 0.0,
                    "security_severity": 0.0,
                }
            }
        },
        {"limits": {"upload": {"max_upload_bytes": -1}}},
        {"probe": {"epochs": "ten"}},
    ],
)
def test_invalid_values_are_errors(overrides):
    with pytest.raises(ConfigError):
        load_scan_config("standard", overrides=overrides)


def test_unknown_profile():
    with pytest.raises(ConfigError):
        load_scan_config("turbo")


def test_overrides_cannot_switch_profile():
    with pytest.raises(ConfigError):
        load_scan_config("standard", overrides={"profile": "deep"})


def test_profile_file_mismatch(tmp_path: Path):
    (tmp_path / "scan_quick.yaml").write_text("profile: deep\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_scan_config("quick", config_dir=tmp_path)


@pytest.mark.parametrize("text", ["probe: [unclosed\n", "- just\n- a list\n"])
def test_bad_yaml(tmp_path: Path, text):
    (tmp_path / "scan_default.yaml").write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        load_scan_config("standard", config_dir=tmp_path)


def test_yaml_is_loaded_safely(tmp_path: Path):
    (tmp_path / "scan_default.yaml").write_text("seed: !!python/object/apply:os.system ['echo hi']\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_scan_config("standard", config_dir=tmp_path)


def test_missing_file(tmp_path: Path):
    with pytest.raises(ConfigError):
        load_scan_config("deep", config_dir=tmp_path)


def test_env_config_dir(tmp_path: Path, monkeypatch):
    (tmp_path / "scan_default.yaml").write_text("probe:\n  knn_k: 9\n", encoding="utf-8")
    monkeypatch.setenv("POISONLENS_CONFIG_DIR", str(tmp_path))
    assert load_scan_config().probe.knn_k == 9


def test_assignment_is_validated():
    cfg = ScanConfig()
    with pytest.raises(ValueError):
        cfg.probe.knn_k = -3  # type: ignore[assignment]
