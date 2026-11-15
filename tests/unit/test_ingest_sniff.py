"""Gate 2: magic-byte sniffing and F01."""

from __future__ import annotations

import io
import pickle
import zipfile

import numpy as np
import pytest

from poisonlens.core.schemas import Severity
from poisonlens.ingest.sniff import f01_findings, sniff
from tests.unit.ingest_fixtures import FAKE_PE, PNG, write_tar, write_zip


def _write(tmp_path, name, data):
    p = tmp_path / ("stored_" + name.replace("/", "_"))
    p.write_bytes(data)
    return p


def test_pe_disguised_as_csv_is_f01(tmp_path):
    p = _write(tmp_path, "data.csv", FAKE_PE)
    res = sniff(p, "data.csv")
    assert res.kind == "pe" and res.mismatch
    (finding,) = f01_findings(res, "data.csv")
    assert finding.check_id == "F01" and finding.severity is Severity.HIGH
    assert "CWE-434" in finding.cwe
    assert "PE" in finding.title


@pytest.mark.parametrize(
    "name,data,kind",
    [
        ("data.csv", b"a,b,label\n1,2,cat\n", "text"),
        ("data.tsv", "a\tb\nü\t2\n".encode(), "text"),
        ("data.json", b'[{"a": 1}]', "json"),
        ("data.jsonl", b'{"a": 1}\n{"a": 2}\n', "json"),
        ("data.xml", b"<?xml version='1.0'?><r/>", "xml"),
        ("utf16.csv", "a,b\n1,2\n".encode("utf-16"), "text"),
        ("img.png", PNG, "png"),
        ("img.jpg", b"\xff\xd8\xff\xe0" + b"\x00" * 20, "jpeg"),
        ("img.gif", b"GIF89a" + b"\x00" * 20, "gif"),
        ("img.webp", b"RIFF\x00\x00\x00\x00WEBPVP8 ", "webp"),
        ("snd.wav", b"RIFF\x24\x00\x00\x00WAVEfmt ", "wav"),
        ("snd.flac", b"fLaC" + b"\x00" * 20, "flac"),
        ("t.parquet", b"PAR1" + b"\x00" * 20 + b"PAR1", "parquet"),
        ("t.feather", b"ARROW1\x00\x00", "arrow"),
        ("t.avro", b"Obj\x01" + b"\x00" * 20, "avro"),
        ("t.h5", b"\x89HDF\r\n\x1a\n" + b"\x00" * 20, "hdf5"),
        ("t.mat", b"MATLAB 7.3 MAT-file".ljust(512, b" ") + b"\x89HDF\r\n\x1a\n", "hdf5"),
        ("t.sqlite", b"SQLite format 3\x00" + b"\x00" * 84, "sqlite"),
        ("t.xls", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 50, "ole2"),
        ("t.sav", b"$FL2@(#) SPSS DATA FILE", "sav"),
        ("x.gz", b"\x1f\x8b\x08\x00" + b"\x00" * 20, "gzip"),
        ("x.bz2", b"BZh91AY&SY", "bz2"),
        ("x.xz", b"\xfd7zXZ\x00\x00", "xz"),
        ("x.7z", b"7z\xbc\xaf\x27\x1c\x00\x04", "7z"),
    ],
)
def test_kinds_consistent(tmp_path, name, data, kind):
    res = sniff(_write(tmp_path, name, data), name)
    assert res.kind == kind
    assert not res.mismatch, res
    assert f01_findings(res, name) == []


def test_npy_and_npz(tmp_path):
    p = tmp_path / "a.npy"
    np.save(p, np.arange(5))
    assert sniff(p, "a.npy").kind == "npy"
    z = tmp_path / "b.npz"
    np.savez(z, x=np.arange(3), y=np.arange(3))
    res = sniff(z, "b.npz")
    assert res.kind == "npz" and not res.mismatch


def test_pickle_bytes_are_detected_never_loaded(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("sniff must never unpickle")

    data = pickle.dumps({"a": 1}, protocol=4)
    monkeypatch.setattr(pickle, "load", boom)
    monkeypatch.setattr(pickle, "loads", boom)
    res = sniff(_write(tmp_path, "m.pkl", data), "m.pkl")
    assert res.kind == "pickle" and not res.mismatch
    res2 = sniff(_write(tmp_path, "m.csv", data), "m.csv")
    assert res2.mismatch and f01_findings(res2, "m.csv")[0].severity is Severity.HIGH


def _ooxml(tmp_path, name, content_type, extra=()):
    p = tmp_path / name
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("[Content_Types].xml", f'<Types><Override ContentType="{content_type}"/></Types>')
        for member in extra:
            zf.writestr(member, b"x")
    return p


def test_xlsx_distinguished_from_zip(tmp_path):
    ct = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
    res = sniff(_ooxml(tmp_path, "book.xlsx", ct), "book.xlsx")
    assert res.kind == "xlsx" and not res.mismatch and not res.macro_enabled
    as_zip = sniff(_ooxml(tmp_path, "book2.zip", ct), "book.zip")
    assert as_zip.kind == "xlsx" and as_zip.mismatch  # OOXML named .zip is not a plain archive


def test_xlsm_macro_flag(tmp_path):
    ct = "application/vnd.ms-excel.sheet.macroEnabled.main+xml"
    res = sniff(_ooxml(tmp_path, "m.xlsm", ct, extra=["xl/vbaProject.bin"]), "m.xlsm")
    assert res.kind == "xlsx" and res.macro_enabled and not res.mismatch


def test_docx_named_xlsx_is_mismatch(tmp_path):
    ct = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"
    res = sniff(_ooxml(tmp_path, "fake.xlsx", ct), "fake.xlsx")
    assert res.kind == "docx" and res.mismatch


def test_ods(tmp_path):
    p = tmp_path / "s.ods"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("mimetype", "application/vnd.oasis.opendocument.spreadsheet")
        zf.writestr("content.xml", "<x/>")
    assert sniff(p, "s.ods").kind == "ods"


def test_plain_zip_and_tar(tmp_path):
    z = write_zip(tmp_path / "a.zip", [("cat/1.png", PNG)])
    assert sniff(z, "a.zip").kind == "zip"
    t = write_tar(tmp_path / "a.tar", [("x.csv", b"1")], mode="w")
    assert sniff(t, "a.tar").kind == "tar"
    tgz = write_tar(tmp_path / "a.tgz", [("x.csv", b"1")])
    res = sniff(tgz, "a.tar.gz")
    assert res.kind == "gzip" and res.claimed_ext == "tar.gz" and not res.mismatch


def test_pytorch_zip_and_jar(tmp_path):
    pt = write_zip(tmp_path / "m.pt", [("archive/data.pkl", b"\x80\x02."), ("archive/version", b"3")])
    assert sniff(pt, "model.pt").kind == "pytorch_zip"
    jar = write_zip(tmp_path / "x.jar", [("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n")])
    res = sniff(jar, "x.zip")
    assert res.kind == "jar" and res.mismatch
    assert f01_findings(res, "x.zip")[0].severity is Severity.HIGH


@pytest.mark.parametrize("magic,kind", [(b"\x7fELF", "elf"), (b"\xcf\xfa\xed\xfe", "macho"), (FAKE_PE, "pe")])
def test_executables_always_flagged(tmp_path, magic, kind):
    res = sniff(_write(tmp_path, "x.bin", magic + b"\x00" * 100), "data.parquet")
    assert res.kind == kind and res.mismatch
    assert f01_findings(res, "data.parquet")[0].severity is Severity.HIGH


def test_png_with_appended_zip_is_polyglot(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("payload.txt", "hidden")
    p = _write(tmp_path, "img.png", PNG + buf.getvalue())
    res = sniff(p, "img.png")
    assert res.kind == "png" and res.polyglot and not res.mismatch
    (finding,) = f01_findings(res, "img.png")
    assert "Polyglot" in finding.title


def test_extension_not_on_allowlist(tmp_path):
    res = sniff(_write(tmp_path, "notes.docm", b"hello"), "notes.docm")
    assert res.mismatch
    assert "allowlist" in f01_findings(res, "notes.docm")[0].title


def test_wrong_but_harmless_type_is_medium(tmp_path):
    res = sniff(_write(tmp_path, "img.png", b"a,b\n1,2\n"), "img.png")
    assert res.kind == "text" and res.mismatch
    assert f01_findings(res, "img.png")[0].severity is Severity.MEDIUM


def test_empty_file(tmp_path):
    res = sniff(_write(tmp_path, "e.csv", b""), "e.csv")
    assert res.kind == "text" and not res.mismatch
