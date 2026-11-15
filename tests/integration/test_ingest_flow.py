"""S0 end to end: upload -> isolated worker ingest_job -> findings, sandbox and ledger."""

from __future__ import annotations

import json

import pytest

from poisonlens.audit.ledger import Ledger
from poisonlens.core.config import ScanConfig
from poisonlens.core.paths import ScanPaths
from poisonlens.ingest.upload import UploadManager
from poisonlens.ingest.worker import run_isolated
from tests.unit.ingest_fixtures import FAKE_PE, PNG, write_zip


def _upload(tmp_path, name: str, data: bytes) -> str:
    cfg = ScanConfig()
    mgr = UploadManager(cfg.limits.upload, data_dir=tmp_path / "data")
    s = mgr.init(name, len(data))
    part = cfg.limits.upload.part_size_bytes
    for n in range(s.n_parts):
        mgr.put_part(s.upload_id, n, data[n * part : (n + 1) * part])
    return mgr.complete(s.upload_id).scan_id


def _ingest(tmp_path, scan_id):
    cfg = ScanConfig()
    res = run_isolated(
        "poisonlens.ingest.jobs:ingest_job",
        {"scan_id": scan_id, "data_dir": str(tmp_path / "data"), "config": cfg.model_dump(mode="json")},
        cfg.limits.worker,
        tmp_path / "work",
    )
    assert res.ok, res
    paths = ScanPaths(scan_id, data_dir=tmp_path / "data")
    findings = json.loads((paths.results / "findings_ingest.json").read_text(encoding="utf-8"))
    ledger = [e["type"] for e in Ledger(paths.audit / "ledger.jsonl").entries()]
    return res.value, findings, ledger, paths


def test_clean_image_zip(tmp_path):
    arc = write_zip(tmp_path / "imgs.zip", [("cat/1.png", PNG), ("dog/1.png", PNG)])
    scan = _upload(tmp_path, "imgs.zip", arc.read_bytes())
    summary, findings, ledger, paths = _ingest(tmp_path, scan)
    assert summary == {
        "halted": False,
        "halt_reason": None,
        "n_findings": 0,
        "max_severity": None,
        "kind": "zip",
        "members": 2,
    }
    assert findings == []
    assert sorted(p.name for p in paths.sandbox.rglob("*.png")) == ["1.png", "1.png"]
    assert ledger == ["SCAN_STARTED", "FILE_ACCEPTED"]


def test_zip_slip_upload_rejected(tmp_path):
    arc = write_zip(tmp_path / "evil.zip", [("ok.png", PNG), ("../../escape.txt", b"pwned")])
    scan = _upload(tmp_path, "evil.zip", arc.read_bytes())
    summary, findings, ledger, paths = _ingest(tmp_path, scan)
    assert summary["halted"] and summary["max_severity"] == "critical"
    assert [f["check_id"] for f in findings] == ["F03"]
    assert list(paths.sandbox.rglob("*")) == []
    assert not list((tmp_path / "data").rglob("escape.txt"))
    assert ledger == ["SCAN_STARTED", "FILE_ACCEPTED", "SECURITY_FINDING", "FILE_REJECTED"]


def test_disguised_executable_rejected(tmp_path):
    scan = _upload(tmp_path, "data.csv", FAKE_PE)
    summary, findings, ledger, _ = _ingest(tmp_path, scan)
    assert summary["halted"] and summary["kind"] == "pe"
    assert [(f["check_id"], f["severity"]) for f in findings] == [("F01", "high")]
    assert ledger[-1] == "FILE_REJECTED"


@pytest.mark.parametrize("name,data", [("train.csv", b"a,b,label\n1,2,x\n"), ("rows.jsonl", b'{"a":1}\n')])
def test_plain_files_pass_through(tmp_path, name, data):
    scan = _upload(tmp_path, name, data)
    summary, findings, ledger, _ = _ingest(tmp_path, scan)
    assert not summary["halted"] and summary["members"] == 0 and findings == []
    assert ledger == ["SCAN_STARTED", "FILE_ACCEPTED"]
