"""Gate 3: every corpus fixture -> correct modality, record count, label candidates and a loadable CDR.

Runs the real S0 (upload + ingest) and S1 (inspect + load) code in-process; the worker
boundary itself is covered by tests/integration.
"""

from __future__ import annotations

import importlib
import json
import pickle

import pandas as pd
import pyarrow.parquet as pq
import pytest

from poisonlens.adapters.jobs import inspect_job, load_job
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.paths import ScanPaths
from poisonlens.core.schemas import DatasetProfile
from poisonlens.ingest.jobs import ingest_job
from poisonlens.ingest.upload import UploadManager
from tests.corpus.make_fixtures import FIXTURES, Fixture, build


def _requires(fx: Fixture) -> None:
    for mod in fx.requires:
        try:
            importlib.import_module(mod)
        except ImportError as exc:
            pytest.skip(f"{fx.name}: optional dependency {mod!r} unavailable ({exc})")


def run_s0_s1(tmp_path, fx: Fixture, selection=None, load=True):
    _requires(fx)
    path = build(fx, tmp_path / "src")
    data = path.read_bytes()
    cfg = ScanConfig()
    data_dir = tmp_path / "data"
    mgr = UploadManager(cfg.limits.upload, data_dir=data_dir)
    s = mgr.init(fx.filename, len(data))
    part = cfg.limits.upload.part_size_bytes
    for n in range(s.n_parts):
        mgr.put_part(s.upload_id, n, data[n * part : (n + 1) * part])
    scan_id = mgr.complete(s.upload_id).scan_id
    args = {"scan_id": scan_id, "data_dir": str(data_dir), "config": cfg.model_dump(mode="json")}
    s0 = ingest_job(args)
    assert not s0["halted"], s0
    profile = DatasetProfile.model_validate(inspect_job({**args, "selection": selection}))
    loaded = load_job({**args, "selection": selection or {}}) if load and profile.capabilities.quality else None
    return profile, loaded, ScanPaths(scan_id, data_dir=data_dir)


@pytest.mark.parametrize("fx", [f for f in FIXTURES if f.name != "pickle"], ids=lambda f: f.name)
def test_fixture_profile_and_cdr(tmp_path, fx):
    profile, loaded, paths = run_s0_s1(tmp_path, fx)

    assert profile.modality.value == fx.modality, profile.adapter
    assert profile.n_records == fx.n_records
    assert profile.label_chosen == fx.label, profile.label_candidates
    if fx.label is not None:
        assert profile.label_candidates and profile.label_candidates[0].column == fx.label
        assert profile.capabilities.labels and profile.capabilities.probe
        assert len(profile.class_hist) == fx.n_classes
    else:
        assert not profile.capabilities.labels and "labels" in profile.capabilities.reasons

    # Loadable CDR
    assert loaded is not None and loaded["n_records"] == fx.n_records
    manifest = pq.read_table(paths.canonical / "manifest.parquet").to_pandas()
    assert len(manifest) == fx.n_records
    assert manifest["record_id"].is_unique
    assert manifest["record_id"].iloc[0] == "r000000000"
    if fx.label is not None:
        assert (manifest["label_idx"] >= 0).all()
        assert sorted(manifest["label_raw"].unique()) == loaded["label_names"]
    final = DatasetProfile.model_validate_json((paths.canonical / "profile.json").read_text(encoding="utf-8"))
    assert final.sampled is False and final.n_records == fx.n_records
    if fx.label is not None:
        assert sum(final.class_hist.values()) == fx.n_records

    if fx.modality in ("tabular",) or (fx.modality == "text" and fx.name in ("hf", "conll")):
        feats = pq.read_table(paths.canonical / "features_raw.parquet").to_pandas()
        assert len(feats) == fx.n_records and list(feats["record_id"]) == list(manifest["record_id"])
    elif fx.modality in ("image", "audio") or fx.name == "text_corpus":
        refs = manifest["payload_ref"]
        assert refs.notna().all()
        for ref in refs.head(5):
            if ref.startswith("array:"):
                assert (paths.canonical / "array_images.npy").exists()
            else:
                assert paths.resolve(ref).is_file(), ref


def test_pickle_is_scan_only_and_never_loaded(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("pickle must never be loaded")

    monkeypatch.setattr(pickle, "load", boom)
    monkeypatch.setattr(pickle, "loads", boom)
    monkeypatch.setattr(pickle, "Unpickler", boom)
    profile, loaded, paths = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "pickle"))
    assert profile.adapter == "serialized"
    assert profile.capabilities.probe is False and profile.capabilities.labels is False
    assert "never" in profile.capabilities.reasons["probe"] or "statically" in profile.capabilities.reasons["probe"]
    assert loaded is None
    with pytest.raises(UnsupportedFormatError):
        load_job({"scan_id": paths.scan_id, "data_dir": str(paths.data_dir), "config": {}})


def test_unlabeled_csv_reason(tmp_path):
    profile, _, _ = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "unlabeled_csv"))
    assert profile.capabilities.labels is False
    assert "No label column" in profile.capabilities.reasons["labels"]
    assert profile.capabilities.probe is False and profile.capabilities.security and profile.capabilities.quality


def test_xlsx_hidden_sheet_listed_not_selected(tmp_path):
    profile, _, paths = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "xlsx"))
    states = {c.name: c.state for c in profile.containers}
    assert states == {"train": "visible", "extra": "visible", "secret": "hidden"}
    assert profile.selection.sheets == ["train", "extra"]
    manifest = pq.read_table(paths.canonical / "manifest.parquet").to_pandas()
    assert manifest["sheet"].value_counts().to_dict() == {"train": 60, "extra": 30}


def test_xlsx_select_hidden_sheet_explicitly(tmp_path):
    fx = next(f for f in FIXTURES if f.name == "xlsx")
    profile, loaded, _ = run_s0_s1(tmp_path, fx, selection={"sheets": ["secret"]})
    assert profile.n_records == 5 and loaded["n_records"] == 5


def test_sav_value_labels_become_names(tmp_path):
    profile, loaded, _ = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "sav"))
    assert loaded["label_names"] == ["bird", "cat", "dog"]


def test_json_nested_flattened_and_container(tmp_path):
    profile, _, paths = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "json"))
    assert profile.selection.container == "records"
    cols = {c.name for c in profile.columns}
    assert {"meta.source", "meta.deep.x"} <= cols
    feats = pq.read_table(paths.canonical / "features_raw.parquet").to_pandas()
    assert pd.api.types.is_integer_dtype(feats["age"]) and pd.api.types.is_float_dtype(feats["income"])


def test_csv_types_inferred_from_strings(tmp_path):
    _, _, paths = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "csv"))
    schema = pq.read_schema(paths.canonical / "features_raw.parquet")
    assert str(schema.field("age").type) == "int64"
    assert str(schema.field("income").type) == "double"
    assert str(schema.field("city").type) == "string"


def test_sqlite_lists_tables_and_picks_largest(tmp_path):
    profile, _, _ = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "sqlite"), load=False)
    assert {c.name: c.n_records for c in profile.containers} == {"samples": 60, "meta": 2}
    assert profile.selection.container == "samples"


def test_image_splits_and_sizes(tmp_path):
    profile, _, paths = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "zip_images"))
    assert profile.splits is not None and profile.splits.counts == {"train": 24, "test": 6}
    manifest = pq.read_table(paths.canonical / "manifest.parquet").to_pandas()
    assert set(manifest["width"]) == {16} and set(manifest["height"]) == {16}
    assert manifest["payload_ref"].str.startswith("sandbox/").all()


@pytest.mark.parametrize("name", ["coco", "yolo", "voc"])
def test_detection_label_is_largest_object(tmp_path, name):
    _, _, paths = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == name))
    manifest = pq.read_table(paths.canonical / "manifest.parquet").to_pandas().sort_values("payload_ref")
    expected = ["cat", "dog", "bird"] * 10  # fixture: big box class i%3, small box class (i+1)%3
    assert manifest["label_raw"].tolist() == expected


def test_conll_is_unlabeled_with_reason(tmp_path):
    profile, _, _ = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "conll"))
    assert "token-level" in profile.capabilities.reasons["labels"]


def test_cifar_class_names_and_splits(tmp_path):
    profile, _, _ = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "cifar"))
    assert set(profile.class_hist) == {"cat", "dog", "bird"}
    assert profile.splits.counts == {"train": 30, "test": 12}


def test_profile_json_round_trips(tmp_path):
    _, _, paths = run_s0_s1(tmp_path, next(f for f in FIXTURES if f.name == "tsv"))
    data = json.loads((paths.canonical / "profile.json").read_text(encoding="utf-8"))
    assert DatasetProfile.model_validate(data).format == "tsv"
