"""S0 -> S1 through the isolated worker, as the pipeline will run it."""

from __future__ import annotations

import pyarrow.parquet as pq

from poisonlens.core.config import ScanConfig
from poisonlens.core.paths import ScanPaths
from poisonlens.ingest.upload import UploadManager
from poisonlens.ingest.worker import run_isolated
from tests.corpus.make_fixtures import BY_NAME, build


def _scan(tmp_path, fx_name):
    fx = BY_NAME[fx_name]
    data = build(fx, tmp_path / "src").read_bytes()
    cfg = ScanConfig()
    mgr = UploadManager(cfg.limits.upload, data_dir=tmp_path / "data")
    s = mgr.init(fx.filename, len(data))
    mgr.put_part(s.upload_id, 0, data)
    scan_id = mgr.complete(s.upload_id).scan_id
    args = {"scan_id": scan_id, "data_dir": str(tmp_path / "data"), "config": cfg.model_dump(mode="json")}
    return cfg, args, ScanPaths(scan_id, data_dir=tmp_path / "data")


def _run(cfg, target, args, tmp_path):
    res = run_isolated(f"poisonlens.{target}", args, cfg.limits.worker, tmp_path / "work")
    assert res.ok, res
    return res.value


def test_image_zip_through_worker(tmp_path):
    cfg, args, paths = _scan(tmp_path, "zip_images")
    _run(cfg, "ingest.jobs:ingest_job", args, tmp_path)
    profile = _run(cfg, "adapters.jobs:inspect_job", args, tmp_path)
    assert profile["modality"] == "image" and profile["label_chosen"] == "folder"
    loaded = _run(cfg, "adapters.jobs:load_job", {**args, "selection": {}}, tmp_path)
    assert loaded["n_records"] == 30 and loaded["label_names"] == ["bird", "cat", "dog"]
    assert pq.read_metadata(paths.canonical / "manifest.parquet").num_rows == 30
    kinds = [e.kind.value for e in __import__("poisonlens.core.events", fromlist=["EventLog"]).EventLog(
        paths.events_file).read_all()]  # fmt: skip
    assert kinds == ["stage_start", "stage_end", "progress", "stage_end"]


def test_user_selection_overrides_label(tmp_path):
    cfg, args, paths = _scan(tmp_path, "csv")
    _run(cfg, "ingest.jobs:ingest_job", args, tmp_path)
    profile = _run(cfg, "adapters.jobs:inspect_job", {**args, "selection": {"label_column": "city"}}, tmp_path)
    assert profile["label_chosen"] == "city" and len(profile["class_hist"]) == 4
    loaded = _run(cfg, "adapters.jobs:load_job", {**args, "selection": {"label_column": "city"}}, tmp_path)
    assert len(loaded["label_names"]) == 4


def test_rejected_upload_cannot_be_inspected(tmp_path):
    from tests.unit.ingest_fixtures import write_zip

    cfg = ScanConfig()
    arc = write_zip(tmp_path / "evil.zip", [("../x.csv", b"a\n1\n")])
    data = arc.read_bytes()
    mgr = UploadManager(cfg.limits.upload, data_dir=tmp_path / "data")
    s = mgr.init("evil.zip", len(data))
    mgr.put_part(s.upload_id, 0, data)
    scan_id = mgr.complete(s.upload_id).scan_id
    args = {"scan_id": scan_id, "data_dir": str(tmp_path / "data"), "config": cfg.model_dump(mode="json")}
    _run(cfg, "ingest.jobs:ingest_job", args, tmp_path)
    res = run_isolated("poisonlens.adapters.jobs:inspect_job", args, cfg.limits.worker, tmp_path / "work")
    assert not res.ok and res.error_type == "UnsafeFileError"
