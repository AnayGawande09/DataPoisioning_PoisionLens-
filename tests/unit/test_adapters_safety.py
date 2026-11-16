"""Adapters treat files as hostile: no writes, no entities, no pickles, bounded keys and pixels."""

from __future__ import annotations

import json
import sqlite3

import numpy as np
import pytest

from poisonlens.adapters.arrays import ArrayAdapter
from poisonlens.adapters.base import Source
from poisonlens.adapters.database import SqliteAdapter, open_readonly
from poisonlens.adapters.image_set import ImageSetAdapter, verify_image
from poisonlens.adapters.jsonfam import JsonAdapter
from poisonlens.adapters.registry import choose_adapter
from poisonlens.adapters.xmlrec import XmlAdapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import LimitExceededError, UnsafeFileError, UnsupportedFormatError
from poisonlens.ingest.sniff import sniff

CFG = ScanConfig()


def _src(path, name=None):
    name = name or path.name
    return Source(path=path, kind=sniff(path, name).kind, name=name)


# ---------------------------------------------------------------- SQLite


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "d.sqlite"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE t (a INTEGER, label TEXT)")
    conn.executemany("INSERT INTO t VALUES (?, ?)", [(i, "x" if i % 2 else "y") for i in range(30)])
    conn.execute("CREATE TABLE log (msg TEXT)")
    conn.execute("CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO log VALUES ('fired'); END")
    conn.commit()
    conn.close()
    return path


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO t VALUES (1, 'z')",
        "DELETE FROM t",
        "DROP TABLE t",
        "CREATE TABLE x (a)",
        "ATTACH DATABASE 'other.db' AS o",
        "PRAGMA writable_schema = 1",
        "SELECT load_extension('evil')",
        "SELECT upper(label) FROM t",  # any function other than count is denied too
    ],
)
def test_sqlite_authorizer_denies(db, sql):
    with open_readonly(db) as conn, pytest.raises(sqlite3.DatabaseError):
        conn.execute(sql)


def test_sqlite_file_unchanged_and_readable(db):
    before = db.read_bytes()
    prof = SqliteAdapter().inspect(_src(db), CFG)
    assert prof.n_records == 30 and prof.selection.container == "t"
    assert db.read_bytes() == before


def test_sqlite_table_name_must_be_listed(db):
    from poisonlens.core.schemas import Selection

    with pytest.raises(UnsupportedFormatError):
        list(SqliteAdapter().iter_raw(_src(db), Selection(container='t"; DROP TABLE t; --'), 10, CFG))


def test_sqlite_virtual_table_not_selectable(tmp_path):
    path = tmp_path / "v.sqlite"
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE VIRTUAL TABLE docs USING fts5(body)")
    except sqlite3.OperationalError:
        pytest.skip("this sqlite build lacks fts5")
    conn.execute("CREATE TABLE t (a)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    conn.close()
    containers = {c.name: c for c in SqliteAdapter().containers(_src(path), CFG)}
    assert containers["docs"].selectable is False and "virtual" in containers["docs"].note


# ---------------------------------------------------------------- XML


def test_xml_entity_bomb_rejected(tmp_path):
    bomb = (
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
        "<dataset><row><a>&lol2;</a></row></dataset>"
    )
    path = tmp_path / "bomb.xml"
    path.write_text(bomb, encoding="utf-8")
    with pytest.raises(UnsafeFileError) as info:
        XmlAdapter().inspect(_src(path), CFG)
    assert info.value.check_id == "F09"


def test_xml_external_entity_rejected(tmp_path):
    xxe = '<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]><d><r><a>&x;</a></r></d>'
    path = tmp_path / "xxe.xml"
    path.write_text(xxe, encoding="utf-8")
    with pytest.raises(UnsafeFileError):
        XmlAdapter().inspect(_src(path), CFG)


# ---------------------------------------------------------------- JSON


def test_json_key_explosion(tmp_path):
    path = tmp_path / "keys.jsonl"
    with open(path, "w", encoding="utf-8") as fh:
        for i in range(3000):
            fh.write(json.dumps({f"k{i}": i, "label": "a"}) + "\n")
    with pytest.raises(LimitExceededError) as info:
        JsonAdapter().inspect(_src(path), CFG)
    assert info.value.limit == "json_max_keys"


def test_json_depth_cap(tmp_path):
    deep: dict = {"label": "a"}
    cur = deep
    for i in range(20):
        cur["n"] = {"v": i}
        cur = cur["n"]
    path = tmp_path / "deep.json"
    path.write_text(json.dumps([deep] * 25), encoding="utf-8")
    prof = JsonAdapter().inspect(_src(path), CFG)
    depths = [c.name.count(".") for c in prof.columns]
    assert max(depths) < CFG.limits.parse.json_max_depth


def test_large_whole_document_json_refused(tmp_path):
    path = tmp_path / "big.json"
    path.write_text(json.dumps([{"a": "x" * 100}] * 2000), encoding="utf-8")
    cfg = CFG.model_copy(deep=True)
    cfg.limits.parse.ram_budget_bytes = 4 * 100_000
    with pytest.raises(LimitExceededError):
        JsonAdapter().inspect(_src(path), cfg)


# ---------------------------------------------------------------- arrays


def test_object_npy_listed_but_never_unpickled(tmp_path, monkeypatch):
    import pickle

    path = tmp_path / "obj.npy"
    np.save(path, np.array([{"a": 1}, None], dtype=object), allow_pickle=True)

    def boom(*a, **k):
        raise AssertionError("must not unpickle")

    monkeypatch.setattr(pickle, "load", boom)
    monkeypatch.setattr(pickle, "loads", boom)
    adapter = ArrayAdapter()
    (c,) = adapter.containers(_src(path), CFG)
    assert c.selectable is False and "pickle" in c.note
    with pytest.raises(UnsupportedFormatError):
        adapter.inspect(_src(path), CFG)


def test_npz_with_object_member_uses_safe_arrays(tmp_path):
    path = tmp_path / "mixed.npz"
    np.savez(path, x=np.zeros((25, 4)), y=np.arange(25) % 2, evil=np.array([object()], dtype=object))
    prof = ArrayAdapter().inspect(_src(path), CFG)
    by = {c.name: c.selectable for c in prof.containers}
    assert by == {"x": True, "y": True, "evil": False}
    assert prof.selection.container == "x" and prof.label_chosen == "y"


# ---------------------------------------------------------------- images


def test_image_pixel_bomb_skipped(tmp_path):
    from PIL import Image

    big = tmp_path / "big.png"
    Image.new("L", (3000, 3000)).save(big)
    assert isinstance(verify_image(big, max_pixels=1_000_000, decode=False), str)
    assert verify_image(big, max_pixels=50_000_000, decode=True) == (3000, 3000)


def test_corrupt_and_svg_images_skipped_with_warnings(tmp_path):
    from PIL import Image

    root = tmp_path / "sandbox"
    for cls in ("a", "b"):
        (root / cls).mkdir(parents=True)
        for i in range(12):
            Image.new("RGB", (8, 8), (i, 0, 0)).save(root / cls / f"{i}.png")
    (root / "a" / "broken.png").write_bytes(b"\x89PNG\r\n\x1a\nnot really")
    (root / "a" / "x.svg").write_text("<svg onload='alert(1)'/>", encoding="utf-8")
    prof = ImageSetAdapter().inspect(Source(root, "directory", "imgs.zip", "sandbox"), CFG)
    assert prof.n_records == 24
    assert any("unreadable" in w for w in prof.warnings)
    assert any("SVG" in w for w in prof.warnings)


# ---------------------------------------------------------------- registry


def test_unsupported_single_file(tmp_path):
    path = tmp_path / "doc.pdf"
    path.write_bytes(b"%PDF-1.4 hello")
    with pytest.raises(UnsupportedFormatError):
        choose_adapter(_src(path))


def test_registry_prefers_specific_adapter(tmp_path):
    root = tmp_path / "hf"
    (root / "train").mkdir(parents=True)
    (root / "train" / "dataset_info.json").write_text("{}", encoding="utf-8")
    (root / "train" / "data-00000-of-00001.arrow").write_bytes(b"")
    (root / "train" / "extra.csv").write_text("a,label\n1,x\n", encoding="utf-8")
    assert choose_adapter(Source(root, "directory", "x.zip", "sandbox")).name == "hf_dataset"
