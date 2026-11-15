"""Gate 2: safe archive extraction (F02 bombs, F03 path safety, F04 hygiene)."""

from __future__ import annotations

import tarfile

import psutil
import pytest

from poisonlens.core.config import ArchiveLimits, MiB
from poisonlens.core.schemas import Severity
from poisonlens.ingest.archive import safe_extract
from tests.unit.ingest_fixtures import (
    PNG,
    nested_zip,
    tar_special,
    write_tar,
    write_zip,
    zeros_gzip_bomb,
    zeros_zip_bomb,
)

LIMITS = ArchiveLimits()


def _ids(report):
    return {(f.check_id, f.severity) for f in report.findings}


def _files(root):
    return sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())


# ---------------------------------------------------------------- benign


def test_folder_per_class_zip(tmp_path):
    arc = write_zip(tmp_path / "imgs.zip", [("cat/1.png", PNG), ("cat/2.png", PNG), ("dog/1.png", PNG)])
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert not rep.halted and rep.findings == []
    assert _files(tmp_path / "out") == ["cat/1.png", "cat/2.png", "dog/1.png"]
    assert {m.path for m in rep.members} == {"cat/1.png", "cat/2.png", "dog/1.png"}
    assert all(len(m.sha256) == 64 and m.size == len(PNG) for m in rep.members)


@pytest.mark.parametrize("mode", ["w", "w:gz", "w:bz2", "w:xz"])
def test_tar_variants(tmp_path, mode):
    arc = write_tar(tmp_path / "d.tar", [("a/x.csv", b"1,2\n"), ("b/y.csv", b"3,4\n")], mode=mode)
    kind = {"w": "tar", "w:gz": "gzip", "w:bz2": "bz2", "w:xz": "xz"}[mode]
    rep = safe_extract(arc, kind, tmp_path / "out", LIMITS)
    assert not rep.halted
    assert _files(tmp_path / "out") == ["a/x.csv", "b/y.csv"]


def test_single_file_gzip(tmp_path):
    import gzip

    arc = tmp_path / "data.csv.gz"
    arc.write_bytes(gzip.compress(b"a,b\n1,2\n"))
    rep = safe_extract(arc, "gzip", tmp_path / "out", LIMITS, label="data.csv.gz")
    assert _files(tmp_path / "out") == ["data.csv"]
    assert rep.members[0].size == 8


def test_extracted_files_are_not_executable(tmp_path):
    import os
    import stat

    arc = write_zip(tmp_path / "a.zip", [("run.sh", b"#!/bin/sh\necho hi\n")])
    safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    mode = os.stat(tmp_path / "out" / "run.sh").st_mode
    assert not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def test_sevenzip(tmp_path):
    py7zr = pytest.importorskip("py7zr", reason="optional dependency py7zr not installed")
    arc = tmp_path / "d.7z"
    with py7zr.SevenZipFile(arc, "w") as zf:
        zf.writestr(PNG, "cat/1.png")
        zf.writestr(b"a,b\n", "labels.csv")
    rep = safe_extract(arc, "7z", tmp_path / "out", LIMITS)
    assert not rep.halted, rep
    assert _files(tmp_path / "out") == ["cat/1.png", "labels.csv"]


# ---------------------------------------------------------------- F03 path safety


@pytest.mark.parametrize(
    "evil",
    ["../evil.txt", "a/../../evil.txt", "/etc/evil.txt", "C:/Windows/evil.txt", "//server/share/evil.txt"],
)
def test_zip_slip_rejected_f03_critical(tmp_path, evil):
    arc = write_zip(tmp_path / "slip.zip", [("ok.csv", b"1\n"), (evil, b"pwned")])
    out = tmp_path / "sandbox" / "out"
    rep = safe_extract(arc, "zip", out, LIMITS)
    assert rep.halted and rep.halt_reason.startswith("F03")
    assert ("F03", Severity.CRITICAL) in _ids(rep)
    assert _files(out) == []  # nothing written, not even the benign member
    assert not (tmp_path / "evil.txt").exists() and not (tmp_path / "sandbox" / "evil.txt").exists()


def test_zip_slip_backslash_variant(tmp_path):
    arc = write_zip(tmp_path / "slip.zip", [("..\\..\\evil.txt", b"x")])
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert rep.halted and ("F03", Severity.CRITICAL) in _ids(rep)


def test_zip_symlink_rejected(tmp_path):
    arc = write_zip(tmp_path / "ln.zip", [("ok.csv", b"1\n")], symlinks={"link": "/etc/passwd"})
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert rep.halted
    f03 = [f for f in rep.findings if f.check_id == "F03"]
    assert f03 and "symlink" in f03[0].title and f03[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    "member,word",
    [
        (tar_special("link", tarfile.SYMTYPE, "/etc/passwd"), "symlink"),
        (tar_special("hard", tarfile.LNKTYPE, "etc/passwd"), "hardlink"),
        (tar_special("dev", tarfile.CHRTYPE), "device"),
        (tar_special("fifo", tarfile.FIFOTYPE), "device"),
    ],
)
def test_tar_links_and_devices_rejected(tmp_path, member, word):
    arc = write_tar(tmp_path / "t.tar.gz", [("ok.csv", b"1\n"), member])
    rep = safe_extract(arc, "gzip", tmp_path / "out", LIMITS)
    assert rep.halted
    assert any(f.check_id == "F03" and word in f.title for f in rep.findings)
    assert _files(tmp_path / "out") == []


def test_tar_absolute_path_rejected(tmp_path):
    arc = write_tar(tmp_path / "t.tar", [("/tmp/evil.txt", b"x")], mode="w")
    rep = safe_extract(arc, "tar", tmp_path / "out", LIMITS)
    assert rep.halted and ("F03", Severity.CRITICAL) in _ids(rep)


def test_no_halt_mode_skips_only_bad_members(tmp_path):
    arc = write_zip(tmp_path / "slip.zip", [("ok.csv", b"1\n"), ("../evil.txt", b"pwned")])
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS, halt_on_critical=False)
    assert not rep.halted
    assert ("F03", Severity.CRITICAL) in _ids(rep)
    assert _files(tmp_path / "out") == ["ok.csv"]
    assert any("evil" in s.source for s in rep.skipped)


# ---------------------------------------------------------------- F02 bombs and limits


@pytest.fixture(scope="module")
def zip_bomb(tmp_path_factory):
    return zeros_zip_bomb(tmp_path_factory.mktemp("bomb") / "bomb.zip")


@pytest.fixture(scope="module")
def gzip_bomb(tmp_path_factory):
    return zeros_gzip_bomb(tmp_path_factory.mktemp("bomb") / "zeros.csv.gz")


def _rss() -> int:
    return psutil.Process().memory_info().rss


def test_zip_bomb_stopped(tmp_path, zip_bomb):
    assert zip_bomb.stat().st_size < 8 * MiB  # 1 GiB of zeros really is tiny compressed
    before = _rss()
    rep = safe_extract(zip_bomb, "zip", tmp_path / "out", LIMITS)
    assert rep.halted and rep.halt_reason.startswith("F02")
    assert ("F02", Severity.HIGH) in _ids(rep)
    assert _files(tmp_path / "out") == []
    assert _rss() - before < 200 * MiB


def test_zip_bomb_stopped_by_streaming_total_cap(tmp_path, zip_bomb):
    # Ratio cap off and declared-size cap above the member: only the streaming total cap can stop it.
    limits = ArchiveLimits(max_compression_ratio=1e9, max_entry_bytes=2 * 1024**3, max_total_bytes=2 * 1024**3)
    limits_small = limits.model_copy(update={"max_total_bytes": 64 * MiB, "max_entry_bytes": 64 * MiB})
    rep = safe_extract(zip_bomb, "zip", tmp_path / "out", limits_small)
    assert rep.halted and "F02" in rep.halt_reason
    assert rep.total_bytes <= 64 * MiB + 64 * 1024


def test_gzip_bomb_without_declared_size_stopped_streaming(tmp_path, gzip_bomb):
    before = _rss()
    rep = safe_extract(gzip_bomb, "gzip", tmp_path / "out", LIMITS, label="zeros.csv.gz")
    assert rep.halted and rep.halt_reason == "F02 max_compression_ratio"
    assert ("F02", Severity.HIGH) in _ids(rep)
    # Stopped as soon as output passed 100x the compressed size, long before the full 1 GiB.
    cap = gzip_bomb.stat().st_size * LIMITS.max_compression_ratio
    assert rep.total_bytes <= cap + 1024 * 1024 and rep.total_bytes < 1024**3
    assert _files(tmp_path / "out") == []
    assert _rss() - before < 200 * MiB


def test_entry_count_cap(tmp_path):
    arc = write_zip(tmp_path / "many.zip", [(f"f{i}.csv", b"1") for i in range(30)])
    rep = safe_extract(arc, "zip", tmp_path / "out", ArchiveLimits(max_entries=25))
    assert rep.halted and any("max_entries" in f.title for f in rep.findings)


def test_nested_depth_3_allowed(tmp_path):
    arc = nested_zip(tmp_path / "n3.zip", 3)
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert not rep.halted, rep.findings
    assert len(rep.nested_archives) == 2
    assert [m.path for m in rep.members] == ["level2.zip.extracted/level3.zip.extracted/data.csv"]
    assert rep.members[0].depth == 3


def test_nested_depth_4_rejected(tmp_path):
    arc = nested_zip(tmp_path / "n4.zip", 4)
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert rep.halted and rep.halt_reason == "F02 max_nesting_depth"
    assert any(f.check_id == "F02" and "nesting" in f.title for f in rep.findings)
    assert _files(tmp_path / "out") == []


def test_nested_zip_slip_also_halts(tmp_path):
    from tests.unit.ingest_fixtures import zip_bytes

    inner = zip_bytes([("../../escape.txt", b"x")])
    arc = write_zip(tmp_path / "outer.zip", [("ok.csv", b"1\n"), ("inner.zip", inner)])
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert rep.halted and ("F03", Severity.CRITICAL) in _ids(rep)
    assert _files(tmp_path / "out") == []


# ---------------------------------------------------------------- F04 hygiene


def test_case_insensitive_collision(tmp_path):
    arc = write_zip(tmp_path / "c.zip", [("Data.csv", b"first"), ("data.CSV", b"second")])
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert not rep.halted
    assert any(f.check_id == "F04" and "collision" in f.title for f in rep.findings)
    files = _files(tmp_path / "out")
    assert files == ["Data.csv"] and (tmp_path / "out" / "Data.csv").read_bytes() == b"first"


def test_duplicate_member_name(tmp_path):
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns about duplicate names
        arc = write_zip(tmp_path / "d.zip", [("x.csv", b"first"), ("x.csv", b"second")])
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert any("collision" in f.title for f in rep.findings)
    assert (tmp_path / "out" / "x.csv").read_bytes() == b"first"


def test_file_vs_directory_collision(tmp_path):
    arc = write_zip(tmp_path / "fd.zip", [("a", b"file"), ("A/b.csv", b"1")])
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert any("collision" in f.title for f in rep.findings)
    assert _files(tmp_path / "out") == ["a"]


@pytest.mark.parametrize(
    "name,expected,reason_word",
    [
        ("CON.txt", "_CON.txt", "reserved"),
        ("nul", "_nul", "reserved"),
        ("report\u202etxt.exe", "reporttxt.exe", "bidi"),
        ("trailing. ", "trailing", "trailing"),
        ("bad<name>?.csv", "bad_name__.csv", "not allowed on Windows"),
        ("x" * 300 + ".csv", None, "over-long"),
    ],
)
def test_hygiene_sanitized_with_f04(tmp_path, name, expected, reason_word):
    arc = write_zip(tmp_path / "h.zip", [(name, b"1")])
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert not rep.halted
    f04 = [f for f in rep.findings if f.check_id == "F04"]
    assert f04 and all(f.severity is Severity.MEDIUM for f in f04)
    assert any(reason_word in f.title for f in f04), [f.title for f in f04]
    (member,) = rep.members
    if expected is not None:
        assert member.path == expected
    else:
        assert len(member.path.encode()) <= 200 and member.path.endswith(".csv")


def test_nul_in_name_skipped(tmp_path):
    # zipfile truncates names at NUL when writing, so write "badX.exe" and patch X -> NUL in the
    # local and central headers. Tools disagree on such names ("bad" vs "bad<NUL>.exe").
    arc = write_zip(tmp_path / "n.zip", [("ok.csv", b"1"), ("badX.exe", b"x")])
    raw = arc.read_bytes()
    assert raw.count(b"badX.exe") == 2
    arc.write_bytes(raw.replace(b"badX.exe", b"bad" + bytes([0]) + b".exe"))
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    assert any(f.check_id == "F04" and "NUL" in f.title for f in rep.findings)
    assert _files(tmp_path / "out") == ["ok.csv"]


def test_findings_are_aggregated_with_examples(tmp_path):
    arc = write_zip(tmp_path / "a.zip", [("PRN.txt", b"1"), ("AUX.csv", b"1"), ("sub/NUL.json", b"1")])
    rep = safe_extract(arc, "zip", tmp_path / "out", LIMITS)
    reserved = [f for f in rep.findings if "reserved" in f.title]
    titles = sorted(f.title for f in reserved)
    assert len(reserved) == 3, titles  # one finding per distinct reason (each device name differs)
    assert all(f.evidence["count"] == 1 and f.evidence["examples"] for f in reserved)
    collide = write_zip(tmp_path / "b.zip", [("x.csv", b"1"), ("X.csv", b"2"), ("x.CSV", b"3")])
    rep2 = safe_extract(collide, "zip", tmp_path / "out2", LIMITS)
    (col,) = [f for f in rep2.findings if "collision" in f.title]
    assert col.evidence["count"] == 2 and len(col.evidence["examples"]) == 2
