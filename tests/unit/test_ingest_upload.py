"""Gate 2: resumable upload (ordering, duplicates, sizes, hashes) and the first ledger entries."""

from __future__ import annotations

import hashlib
import json
import os
import random

import pytest

from poisonlens.core.config import UploadLimits
from poisonlens.core.errors import (
    IntegrityError,
    LimitExceededError,
    PathSafetyError,
    UnsafeFileError,
    UploadStateError,
)
from poisonlens.core.paths import ScanPaths
from poisonlens.ingest.upload import UploadManager, stored_extension

PART = 1024


@pytest.fixture
def mgr(tmp_path):
    limits = UploadLimits(part_size_bytes=PART, max_upload_bytes=1024 * 1024, disk_quota_bytes=10 * 1024 * 1024)
    return UploadManager(limits, data_dir=tmp_path)


def _parts(data: bytes):
    return [data[i : i + PART] for i in range(0, len(data), PART)]


def _blob(n=PART * 3 + 100, seed=0):
    return random.Random(seed).randbytes(n)


def test_out_of_order_upload(mgr, tmp_path):
    data = _blob()
    s = mgr.init("train.csv", len(data), sha256=hashlib.sha256(data).hexdigest())
    parts = _parts(data)
    assert s.n_parts == 4
    for n in [3, 1, 0, 2]:
        mgr.put_part(s.upload_id, n, parts[n])
    done = mgr.complete(s.upload_id)

    paths = ScanPaths(done.scan_id, data_dir=tmp_path)
    stored = paths.resolve(done.stored_path)
    assert stored.read_bytes() == data
    assert done.sha256 == hashlib.sha256(data).hexdigest()
    assert done.stored_path == "upload/original.csv"  # generated name; original name only in metadata
    meta = json.loads((paths.upload / "meta.json").read_text(encoding="utf-8"))
    assert meta["original_name"] == "train.csv"
    assert not (tmp_path / "uploads" / s.upload_id).exists()  # session cleaned up


def test_ledger_started_and_accepted(mgr, tmp_path):
    from poisonlens.audit.ledger import GENESIS_HASH, Ledger, entry_hash

    data = _blob(10)
    s = mgr.init("x.csv", len(data))
    mgr.put_part(s.upload_id, 0, data)
    done = mgr.complete(s.upload_id)
    entries = Ledger(ScanPaths(done.scan_id, data_dir=tmp_path).audit / "ledger.jsonl").entries()
    assert [e["type"] for e in entries] == ["SCAN_STARTED", "FILE_ACCEPTED"]
    assert entries[0]["payload"]["dataset_sha256"] == done.sha256
    assert entries[0]["prev"] == GENESIS_HASH and entries[1]["prev"] == entries[0]["hash"]
    for e in entries:
        body = {k: e[k] for k in ("i", "ts", "type", "payload")}
        assert e["hash"] == entry_hash(e["prev"], body)


def test_duplicate_identical_part_is_idempotent(mgr):
    data = _blob()
    s = mgr.init("a.csv", len(data))
    parts = _parts(data)
    first = mgr.put_part(s.upload_id, 0, parts[0])
    again = mgr.put_part(s.upload_id, 0, parts[0])
    assert first == again


def test_duplicate_conflicting_part_rejected(mgr):
    data = _blob()
    s = mgr.init("a.csv", len(data))
    mgr.put_part(s.upload_id, 0, _parts(data)[0])
    with pytest.raises(IntegrityError, match="different content"):
        mgr.put_part(s.upload_id, 0, bytes(PART))


@pytest.mark.parametrize("n,size", [(0, PART - 1), (0, PART + 1), (3, PART), (3, 99)])
def test_wrong_part_size(mgr, n, size):
    s = mgr.init("a.csv", PART * 3 + 100)
    with pytest.raises(IntegrityError, match="expected"):
        mgr.put_part(s.upload_id, n, bytes(size))


@pytest.mark.parametrize("n", [-1, 4, 100])
def test_part_number_out_of_range(mgr, n):
    s = mgr.init("a.csv", PART * 3 + 100)
    with pytest.raises(UploadStateError):
        mgr.put_part(s.upload_id, n, bytes(PART))


def test_part_hash_mismatch(mgr):
    s = mgr.init("a.csv", PART)
    with pytest.raises(IntegrityError, match="sha256"):
        mgr.put_part(s.upload_id, 0, bytes(PART), sha256="0" * 64)


def test_wrong_final_hash_discards_everything(mgr, tmp_path):
    data = _blob()
    s = mgr.init("a.csv", len(data), sha256="f" * 64)
    for n, p in enumerate(_parts(data)):
        mgr.put_part(s.upload_id, n, p)
    with pytest.raises(IntegrityError, match="final sha256"):
        mgr.complete(s.upload_id)
    scans = tmp_path / "scans"
    assert not scans.exists() or list(scans.iterdir()) == []
    assert not (tmp_path / "uploads" / s.upload_id).exists()


def test_part_tampered_on_disk_detected(mgr, tmp_path):
    data = _blob(PART * 2)
    s = mgr.init("a.csv", len(data))
    for n, p in enumerate(_parts(data)):
        mgr.put_part(s.upload_id, n, p)
    part_file = tmp_path / "uploads" / s.upload_id / "parts" / "000001.part"
    part_file.write_bytes(bytes(PART))
    with pytest.raises(IntegrityError, match="changed on disk"):
        mgr.complete(s.upload_id)


def test_missing_parts(mgr):
    data = _blob()
    s = mgr.init("a.csv", len(data))
    mgr.put_part(s.upload_id, 0, _parts(data)[0])
    with pytest.raises(UploadStateError, match=r"missing parts: \[1, 2, 3\]"):
        mgr.complete(s.upload_id)


def test_resume_from_status(mgr):
    data = _blob()
    s = mgr.init("a.csv", len(data))
    parts = _parts(data)
    mgr.put_part(s.upload_id, 2, parts[2])
    # a "new client" asks which parts are still missing and sends only those
    missing = mgr.status(s.upload_id).missing_parts()
    assert missing == [0, 1, 3]
    for n in missing:
        mgr.put_part(s.upload_id, n, parts[n])
    assert mgr.complete(s.upload_id).size == len(data)


def test_cannot_complete_twice_or_use_after_complete(mgr):
    data = _blob(10)
    s = mgr.init("a.csv", len(data))
    mgr.put_part(s.upload_id, 0, data)
    mgr.complete(s.upload_id)
    with pytest.raises(UploadStateError):
        mgr.complete(s.upload_id)
    with pytest.raises(UploadStateError):
        mgr.put_part(s.upload_id, 0, data)


@pytest.mark.parametrize("bad", ["../etc", "a" * 31, "A" * 32, "x" * 64, "0" * 31 + "/"])
def test_invalid_upload_ids(mgr, bad):
    with pytest.raises(PathSafetyError):
        mgr.status(bad)


@pytest.mark.parametrize(
    "name",
    ["", "   ", "a/b.csv", "..\\b.csv", "..", "bad\x00.csv", "evil‮csv.exe", "tab\there.csv", "x" * 300],
)
def test_bad_filenames_rejected(mgr, name):
    with pytest.raises(UnsafeFileError) as info:
        mgr.init(name, 10)
    assert info.value.check_id == "F04"


def test_size_limits(mgr):
    with pytest.raises(LimitExceededError):
        mgr.init("a.csv", 0)
    with pytest.raises(LimitExceededError) as info:
        mgr.init("a.csv", 1024 * 1024 + 1)
    assert info.value.limit == "max_upload_bytes"


def test_disk_quota(tmp_path):
    limits = UploadLimits(part_size_bytes=PART, max_upload_bytes=1024 * 1024, disk_quota_bytes=4096)
    mgr = UploadManager(limits, data_dir=tmp_path)
    (tmp_path / "scans" / "scan_existing0").mkdir(parents=True)
    (tmp_path / "scans" / "scan_existing0" / "blob").write_bytes(bytes(4000))
    with pytest.raises(LimitExceededError) as info:
        mgr.init("a.csv", 200)
    assert info.value.limit == "disk_quota_bytes"


def test_stored_file_not_executable(mgr, tmp_path):
    import stat

    data = b"#!/bin/sh\n"
    s = mgr.init("run.sh", len(data))
    mgr.put_part(s.upload_id, 0, data)
    done = mgr.complete(s.upload_id)
    mode = os.stat(ScanPaths(done.scan_id, data_dir=tmp_path).resolve(done.stored_path)).st_mode
    assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.mark.parametrize(
    "name,ext",
    [
        ("Data.CSV", "csv"),
        ("x.tar.gz", "tar.gz"),
        ("x.TGZ", "tgz"),
        ("noext", "bin"),
        (".hidden", "bin"),
        ("weird.e x e", "bin"),
        ("a.verylongextension", "bin"),
    ],
)
def test_stored_extension(name, ext):
    assert stored_extension(name) == ext
