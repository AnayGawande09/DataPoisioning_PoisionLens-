"""ScanPaths: scan-id validation and traversal-proof resolution."""

import os
from pathlib import Path

import pytest

from poisonlens.core.errors import PathSafetyError
from poisonlens.core.paths import SUBDIRS, ScanPaths, validate_scan_id

GOOD_ID = "scan_0123abcd"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "short",  # < 8
        "a" * 65,  # > 64
        "../abcdefgh",
        "abcd/efgh",
        "abcd\\efgh",
        "abcdefgh%2f",
        "abcdefgh..",
        "abc defgh",
        "abcdéfghi",
        "abcdefgh\x00",
        "C:abcdefgh",
    ],
)
def test_bad_scan_ids(bad, tmp_path):
    with pytest.raises(PathSafetyError):
        validate_scan_id(bad)
    with pytest.raises(PathSafetyError):
        ScanPaths(bad, data_dir=tmp_path)


@pytest.mark.parametrize("good", ["abcdefgh", "A" * 64, "scan-2026_11-16"])
def test_good_scan_ids(good):
    assert validate_scan_id(good) == good


def test_layout(tmp_path):
    sp = ScanPaths(GOOD_ID, data_dir=tmp_path).ensure()
    root = (tmp_path / "scans" / GOOD_ID).resolve()
    assert sp.root == root
    for name in SUBDIRS:
        assert getattr(sp, name) == root / name
        assert (root / name).is_dir()
    assert sp.events_file == root / "events.jsonl"
    assert sp.state_file == root / "state.json"


def test_ensure_is_idempotent(tmp_path):
    ScanPaths(GOOD_ID, data_dir=tmp_path).ensure().ensure()


@pytest.mark.parametrize(
    "rel",
    [
        "../x",
        "..",
        "..\\x",
        "a/../../x",
        "results/../../other_scan/x",
        "/etc/passwd",
        "\\windows\\system32",
        "C:\\Windows\\win.ini",
        "C:foo",
        "\\\\server\\share\\x",
        "//server/share/x",
        "%2e%2e/x",
        "%2e%2e%2fx",
        "..%2fx",
        "..%5cx",
        "%252e%252e%252fx",  # double-encoded
        "%2fetc%2fpasswd",
        "results/file.json:stream",  # NTFS alternate data stream
        "x\x00.json",
        "",
    ],
)
def test_resolve_rejects_escapes(tmp_path, rel):
    sp = ScanPaths(GOOD_ID, data_dir=tmp_path).ensure()
    with pytest.raises(PathSafetyError):
        sp.resolve(rel)


@pytest.mark.parametrize("rel", ["results/report.json", "export/clean.csv", "audit/ledger.jsonl", "a/b/c.txt"])
def test_resolve_accepts_inside(tmp_path, rel):
    sp = ScanPaths(GOOD_ID, data_dir=tmp_path)
    assert sp.resolve(rel) == (sp.root / rel).resolve()


def test_resolve_rejects_symlink_escape(tmp_path):
    sp = ScanPaths(GOOD_ID, data_dir=tmp_path / "data").ensure()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = sp.results / "link"
    try:
        os.symlink(outside, link, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # Windows without Developer Mode / admin
        pytest.skip(f"symlinks unavailable here: {exc}")
    with pytest.raises(PathSafetyError):
        sp.resolve("results/link/secret.txt")


@pytest.mark.skipif(os.name != "nt", reason="extended-length prefix is Windows-only")
def test_os_path_long_windows_paths():
    from poisonlens.core.paths import os_path

    prefix = "\\\\?\\"
    assert len(prefix) == 4
    long_local = "C:\\" + "a" * 250
    assert os_path(long_local) == prefix + long_local
    long_unc = "\\\\srv\\share\\" + "a" * 240
    assert os_path(long_unc) == prefix + "UNC\\srv\\share\\" + "a" * 240
    assert os_path(prefix + long_local) == prefix + long_local  # idempotent
    assert os_path("C:\\short") == "C:\\short"


def test_os_path_long_file_roundtrip(tmp_path):
    from poisonlens.core.paths import os_path

    deep = tmp_path.joinpath(*(["d" * 50] * 6))  # > 260 characters in total
    os.makedirs(os_path(deep), exist_ok=True)
    target = deep / ("f" * 100 + ".txt")
    with open(os_path(target), "wb") as fh:
        fh.write(b"ok")
    with open(os_path(target), "rb") as fh:
        assert fh.read() == b"ok"


def test_env_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("POISONLENS_DATA_DIR", str(tmp_path))
    assert ScanPaths(GOOD_ID).root == (tmp_path / "scans" / GOOD_ID).resolve()


def test_default_data_dir_is_repo_data(monkeypatch):
    monkeypatch.delenv("POISONLENS_DATA_DIR", raising=False)
    repo = Path(__file__).resolve().parents[2]
    assert ScanPaths(GOOD_ID).root == (repo / "data" / "scans" / GOOD_ID).resolve()
