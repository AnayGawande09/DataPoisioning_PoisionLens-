"""Quick-demo pipeline: planted problems are found, the control stays clean, unsafe files stop early."""

from __future__ import annotations

import pickle
from pathlib import Path

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from poisonlens.core.paths import ScanPaths
from poisonlens.demo.pipeline import run_demo_scan
from poisonlens.demo.samples import build


def _scan(name: str, tmp_path: Path) -> tuple[dict, dict]:
    data, truth = build(name)
    return run_demo_scan([data], name, len(data), data_dir=tmp_path), truth


def _review(report: dict, tmp_path: Path) -> pd.DataFrame:
    return pd.read_csv(ScanPaths(report["scan_id"], data_dir=tmp_path).root / "export" / "review.csv")


@pytest.mark.parametrize("name", ["loans_poisoned.csv", "reviews_poisoned.csv"])
def test_poisoned_tables_are_caught(name: str, tmp_path: Path) -> None:
    r, truth = _scan(name, tmp_path)
    assert r["verdict"] == "likely_poisoned"
    assert r["ledger"]["verified"]
    rv = _review(r, tmp_path)
    flagged = set(rv.record_id)
    planted = {f"r{i:09d}" for i in truth["flipped_rows"] + truth["backdoor_rows"]}
    backdoor = {f"r{i:09d}" for i in truth["backdoor_rows"]}
    quarantined = set(rv[rv.tier == "quarantine"].record_id)
    assert len(planted & flagged) / len(planted) >= 0.9
    assert backdoor <= quarantined
    assert len(planted & quarantined) / len(quarantined) >= 0.8  # quarantine precision
    assert r["triggers"] and r["triggers"][0]["value"] in ("ZX-77", "cf")


def test_image_patch_trigger(tmp_path: Path) -> None:
    r, truth = _scan("shapes_poisoned.zip", tmp_path)
    assert r["triggers"][0]["where"] == "corner_patch"
    man = pd.read_parquet(ScanPaths(r["scan_id"], data_dir=tmp_path).canonical / "manifest.parquet")
    bad = set(man[man.payload_ref.isin(["sandbox/" + f for f in truth["poisoned_files"]])].record_id)
    rv = _review(r, tmp_path)
    assert bad <= set(rv[rv.tier == "quarantine"].record_id)


def test_clean_control_is_clean(tmp_path: Path) -> None:
    r, _ = _scan("loans_clean.csv", tmp_path)
    assert r["verdict"] == "clean"
    assert not r["triggers"]


def test_pickle_is_never_loaded(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*a: object, **k: object) -> None:
        raise AssertionError("pickle must not be loaded")

    monkeypatch.setattr(pickle, "load", boom)
    monkeypatch.setattr(pickle, "loads", boom)
    data = pickle.dumps({"x": 1})
    r = run_demo_scan([data], "model.pkl", len(data), data_dir=tmp_path)
    assert r["verdict"] == "unsafe_file"
    assert [f["check_id"] for f in r["findings"]] == ["F07"]


def test_formula_cells_escaped_in_export(tmp_path: Path) -> None:
    r, _ = _scan("loans_poisoned.csv", tmp_path)
    text = (ScanPaths(r["scan_id"], data_dir=tmp_path).root / "export" / "cleaned.csv").read_text(encoding="utf-8")
    assert "'=HYPERLINK" in text and ",=HYPERLINK" not in text


def test_api_download_refuses_traversal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("POISONLENS_DATA_DIR", str(tmp_path))
    from backend.main import app

    c = TestClient(app)
    assert c.get("/").status_code == 200
    assert c.get("/api/demo/scans/scan_..%2F..%2Fx/download/report.json").status_code in (400, 404)
    assert c.get("/api/demo/scans/scan_0123456789abcdef/download/../../x").status_code == 404
    assert c.get("/api/demo/samples/..%2Fsecret").status_code == 404
