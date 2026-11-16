"""Gate 3 corpus: a tiny, valid dataset in every supported format.

Each :class:`Fixture` builds one upload file into a directory and states what S1 must
detect. Optional dependencies are declared per fixture so tests skip with a reason.

    .venv\\Scripts\\python -m tests.corpus.make_fixtures <out_dir>
"""

from __future__ import annotations

import io
import json
import pickle
import sqlite3
import struct
import sys
import tarfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

N = 60
CLASSES = ["cat", "dog", "bird"]


def base_frame(n: int = N, seed: int = 0) -> pd.DataFrame:
    rng = np.random.RandomState(seed)
    return pd.DataFrame(
        {
            "age": rng.randint(18, 80, n),
            "income": np.round(rng.normal(50_000, 12_000, n), 2),
            "city": rng.choice(["Pune", "Delhi", "Mumbai", "Chennai"], n),
            "label": [CLASSES[i % 3] for i in range(n)],
        }
    )


@dataclass
class Fixture:
    name: str
    filename: str
    build: Callable[[Path], None]  # writes out_dir / filename
    modality: str
    n_records: int
    label: str | None  # expected pre-selected label (None => unlabeled)
    requires: tuple[str, ...] = ()
    n_classes: int = 3
    extra: dict[str, object] = field(default_factory=dict)


# ---------------------------------------------------------------------------- tabular


def _csv(path: Path) -> None:
    base_frame().to_csv(path, index=False)


def _tsv(path: Path) -> None:
    base_frame().to_csv(path, sep="\t", index=False)


def _csv_gz(path: Path) -> None:
    import gzip

    path.write_bytes(gzip.compress(base_frame().to_csv(index=False).encode()))


def _unlabeled_csv(path: Path) -> None:
    df = base_frame().drop(columns=["label"])
    df["height_cm"] = np.linspace(150, 190, N).round(1)
    df.to_csv(path, index=False)


def _xlsx(path: Path) -> None:
    import openpyxl

    wb = openpyxl.Workbook()
    df = base_frame()
    for title, frame, state in (
        ("train", df, "visible"),
        ("extra", base_frame(30, 1), "visible"),
        ("secret", base_frame(5, 2), "hidden"),
    ):
        ws = wb.active if title == "train" else wb.create_sheet(title)
        ws.title = title
        ws.sheet_state = state
        ws.append(list(frame.columns))
        for row in frame.itertuples(index=False):
            ws.append([v.item() if hasattr(v, "item") else v for v in row])
    wb.save(path)


def _xls(path: Path) -> None:
    import xlwt

    wb = xlwt.Workbook()
    ws = wb.add_sheet("data")
    df = base_frame()
    for j, c in enumerate(df.columns):
        ws.write(0, j, c)
    for i, row in enumerate(df.itertuples(index=False), start=1):
        for j, v in enumerate(row):
            ws.write(i, j, v.item() if hasattr(v, "item") else v)
    wb.save(str(path))


def _ods(path: Path) -> None:
    base_frame().to_excel(path, engine="odf", index=False, sheet_name="data")


def _json(path: Path) -> None:
    recs = base_frame().to_dict(orient="records")
    for i, r in enumerate(recs):
        r["meta"] = {"source": f"s{i % 4}", "deep": {"x": i}}
    path.write_text(json.dumps({"version": 1, "records": recs}, default=int), encoding="utf-8")


def _jsonl(path: Path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for r in base_frame().to_dict(orient="records"):
            fh.write(json.dumps(r, default=int) + "\n")


def _parquet(path: Path) -> None:
    base_frame().to_parquet(path, index=False)


def _feather(path: Path) -> None:
    base_frame().to_feather(path)


def _orc(path: Path) -> None:
    import pyarrow as pa
    from pyarrow import orc

    orc.write_table(pa.Table.from_pandas(base_frame(), preserve_index=False), str(path))


def _avro(path: Path) -> None:
    import fastavro

    schema = {
        "type": "record",
        "name": "Row",
        "fields": [
            {"name": "age", "type": "long"},
            {"name": "income", "type": "double"},
            {"name": "city", "type": "string"},
            {"name": "label", "type": "string"},
        ],
    }
    recs = [
        {"age": int(r.age), "income": float(r.income), "city": r.city, "label": r.label}
        for r in base_frame().itertuples()
    ]
    with open(path, "wb") as fh:
        fastavro.writer(fh, fastavro.parse_schema(schema), recs)


def _sav(path: Path) -> None:
    import pyreadstat

    df = base_frame()
    df["label"] = [CLASSES.index(v) + 1 for v in df["label"]]  # coded; value labels give the names
    pyreadstat.write_sav(df, str(path), variable_value_labels={"label": {1: "cat", 2: "dog", 3: "bird"}})


def _dta(path: Path) -> None:
    import pyreadstat

    pyreadstat.write_dta(base_frame(), str(path))


def _sqlite(path: Path) -> None:
    conn = sqlite3.connect(path)
    base_frame().to_sql("samples", conn, index=False)
    conn.execute("CREATE TABLE meta (k TEXT, v TEXT)")
    conn.executemany("INSERT INTO meta VALUES (?, ?)", [("a", "1"), ("b", "2")])
    conn.commit()
    conn.close()


def _xml(path: Path) -> None:
    rows = []
    for r in base_frame().itertuples():
        rows.append(
            f'<sample id="{r.Index}"><age>{r.age}</age><income>{r.income}</income>'
            f"<city>{r.city}</city><label>{r.label}</label></sample>"
        )
    path.write_text("<?xml version='1.0'?><dataset>" + "".join(rows) + "</dataset>", encoding="utf-8")


# ---------------------------------------------------------------------------- arrays


def _images(n: int, size: int = 16, seed: int = 0) -> np.ndarray:
    return np.random.RandomState(seed).randint(0, 256, (n, size, size, 3), dtype=np.uint8)


def _npy(path: Path) -> None:
    np.save(path, _images(N))


def _npz(path: Path) -> None:
    np.savez(path, x=_images(N), y=np.array([i % 3 for i in range(N)]))


def _hdf5(path: Path) -> None:
    import h5py

    with h5py.File(path, "w") as f:
        f["X"] = np.random.RandomState(0).normal(size=(N, 5))
        f["y"] = np.array([i % 3 for i in range(N)])


# ---------------------------------------------------------------------------- image / audio / text sets


def _png(seed: int, size: int = 16) -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.fromarray(_images(1, size, seed)[0]).save(buf, format="PNG")
    return buf.getvalue()


def _jpg(seed: int) -> bytes:
    from PIL import Image

    buf = io.BytesIO()
    Image.fromarray(_images(1, 16, seed)[0]).save(buf, format="JPEG")
    return buf.getvalue()


PER_CLASS = 10


def image_folder_members() -> list[tuple[str, bytes]]:
    out = []
    for c, cls in enumerate(CLASSES):
        for i in range(PER_CLASS):
            split = "train" if i < 8 else "test"
            out.append((f"{split}/{cls}/{cls}_{i}.png", _png(c * 100 + i)))
    return out


def _zip(path: Path, members: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members:
            zf.writestr(name, data)


def _tar(path: Path, members: list[tuple[str, bytes]], mode: str) -> None:
    with tarfile.open(path, mode) as tf:
        for name, data in members:
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


def _img_zip(path: Path) -> None:
    _zip(path, image_folder_members())


def _img_tar(path: Path) -> None:
    _tar(path, image_folder_members(), "w")


def _img_tgz(path: Path) -> None:
    _tar(path, image_folder_members(), "w:gz")


def _img_7z(path: Path) -> None:
    import py7zr

    with py7zr.SevenZipFile(path, "w") as zf:
        for name, data in image_folder_members():
            zf.writestr(data, name)


def _coco(path: Path) -> None:
    members, images, anns = [], [], []
    for i in range(30):
        name = f"img_{i:03d}.png"
        members.append((f"images/{name}", _png(i)))
        images.append({"id": i, "file_name": name, "width": 16, "height": 16})
        anns.append({"id": 2 * i, "image_id": i, "category_id": i % 3 + 1, "bbox": [0, 0, 10, 10], "area": 100})
        anns.append({"id": 2 * i + 1, "image_id": i, "category_id": (i + 1) % 3 + 1, "bbox": [0, 0, 2, 2], "area": 4})
    cats = [{"id": k + 1, "name": n} for k, n in enumerate(CLASSES)]
    members.append(
        ("annotations/instances.json", json.dumps({"images": images, "annotations": anns, "categories": cats}).encode())
    )
    _zip(path, members)


def _yolo(path: Path) -> None:
    members = [("classes.txt", "\n".join(CLASSES).encode())]
    for i in range(30):
        members.append((f"images/img_{i:03d}.png", _png(i)))
        members.append(
            (f"labels/img_{i:03d}.txt", f"{i % 3} 0.5 0.5 0.6 0.6\n{(i + 1) % 3} 0.1 0.1 0.05 0.05\n".encode())
        )
    _zip(path, members)


def _voc(path: Path) -> None:
    members = []
    for i in range(30):
        members.append((f"JPEGImages/img_{i:03d}.jpg", _jpg(i)))
        xml = (
            f"<annotation><filename>img_{i:03d}.jpg</filename>"
            f"<object><name>{CLASSES[i % 3]}</name><bndbox><xmin>0</xmin><ymin>0</ymin><xmax>12</xmax><ymax>12</ymax></bndbox></object>"
            f"<object><name>{CLASSES[(i + 1) % 3]}</name><bndbox><xmin>0</xmin><ymin>0</ymin><xmax>2</xmax><ymax>2</ymax></bndbox></object>"
            "</annotation>"
        )
        members.append((f"Annotations/img_{i:03d}.xml", xml.encode()))
    _zip(path, members)


def _img_manifest(path: Path) -> None:
    members = [(f"imgs/{i:03d}.png", _png(i)) for i in range(30)]
    members.append(
        ("labels.csv", ("filename,label\n" + "".join(f"{i:03d}.png,{CLASSES[i % 3]}\n" for i in range(30))).encode())
    )
    _zip(path, members)


def _wav(seed: int) -> bytes:
    import soundfile as sf

    t = np.linspace(0, 0.1, 1600, endpoint=False)
    buf = io.BytesIO()
    sf.write(buf, (0.3 * np.sin(2 * np.pi * (200 + 40 * seed) * t)).astype(np.float32), 16000, format="WAV")
    return buf.getvalue()


def _audio_zip(path: Path) -> None:
    _zip(path, [(f"{cls}/{cls}_{i}.wav", _wav(i)) for cls in ("yes", "no") for i in range(12)])


def _text_corpus(path: Path) -> None:
    words = {"pos": "great wonderful loved it", "neg": "awful boring hated it"}
    _zip(path, [(f"{cls}/{i}.txt", f"Review {i}: {words[cls]} {i}".encode()) for cls in words for i in range(12)])


def _conll(path: Path) -> None:
    sents = ["John B-PER\nlives O\nin O\nPune B-LOC\n", "Mary B-PER\nworks O\n"] * 15
    path.write_text("\n".join(sents), encoding="utf-8")


# ---------------------------------------------------------------------------- ML-native


def _cifar(path: Path) -> None:
    rng = np.random.RandomState(0)

    def batch(n: int, offset: int) -> bytes:
        out = bytearray()
        for i in range(n):
            out.append((i + offset) % 3)
            out += rng.randint(0, 256, 3072, dtype=np.uint8).tobytes()
        return bytes(out)

    _zip(
        path,
        [
            ("cifar-10-batches-bin/data_batch_1.bin", batch(30, 0)),
            ("cifar-10-batches-bin/test_batch.bin", batch(12, 1)),
            ("cifar-10-batches-bin/batches.meta.txt", "\n".join(CLASSES).encode()),
        ],
    )


def _idx(dims: tuple[int, ...], data: np.ndarray) -> bytes:
    return bytes([0, 0, 0x08, len(dims)]) + struct.pack(">" + "I" * len(dims), *dims) + data.astype(np.uint8).tobytes()


def _mnist(path: Path) -> None:
    rng = np.random.RandomState(0)
    tr, te = 30, 10
    _zip(
        path,
        [
            ("train-images-idx3-ubyte", _idx((tr, 28, 28), rng.randint(0, 256, (tr, 28, 28)))),
            ("train-labels-idx1-ubyte", _idx((tr,), np.arange(tr) % 3)),
            ("t10k-images-idx3-ubyte", _idx((te, 28, 28), rng.randint(0, 256, (te, 28, 28)))),
            ("t10k-labels-idx1-ubyte", _idx((te,), np.arange(te) % 3)),
        ],
    )


def _hf(path: Path) -> None:
    import pyarrow as pa

    texts = [f"sample review number {i} with some words" for i in range(N)]
    table = pa.table({"text": texts, "label": pa.array([i % 2 for i in range(N)], pa.int64())})
    sink = pa.BufferOutputStream()
    with pa.ipc.new_stream(sink, table.schema) as w:
        w.write_table(table)
    info = {
        "features": {
            "text": {"dtype": "string", "_type": "Value"},
            "label": {"names": ["neg", "pos"], "_type": "ClassLabel"},
        }
    }
    _zip(
        path,
        [
            ("ds/train/data-00000-of-00001.arrow", sink.getvalue().to_pybytes()),
            ("ds/train/dataset_info.json", json.dumps(info).encode()),
            ("ds/train/state.json", b'{"_data_files": [{"filename": "data-00000-of-00001.arrow"}]}'),
        ],
    )


def _pickle(path: Path) -> None:
    path.write_bytes(pickle.dumps({"weights": [1, 2, 3]}, protocol=4))


FIXTURES: list[Fixture] = [
    Fixture("csv", "data.csv", _csv, "tabular", N, "label"),
    Fixture("tsv", "data.tsv", _tsv, "tabular", N, "label"),
    Fixture("csv_gz", "data.csv.gz", _csv_gz, "tabular", N, "label"),
    Fixture("unlabeled_csv", "people.csv", _unlabeled_csv, "tabular", N, None),
    Fixture("xlsx", "book.xlsx", _xlsx, "tabular", N + 30, "label", ("openpyxl",)),
    Fixture("xls", "book.xls", _xls, "tabular", N, "label", ("xlwt", "xlrd")),
    Fixture("ods", "book.ods", _ods, "tabular", N, "label", ("odf",)),
    Fixture("json", "data.json", _json, "tabular", N, "label"),
    Fixture("jsonl", "data.jsonl", _jsonl, "tabular", N, "label"),
    Fixture("parquet", "data.parquet", _parquet, "tabular", N, "label", ("pyarrow.parquet",)),
    Fixture("feather", "data.feather", _feather, "tabular", N, "label", ("pyarrow.feather",)),
    Fixture("orc", "data.orc", _orc, "tabular", N, "label", ("pyarrow.orc",)),
    Fixture("avro", "data.avro", _avro, "tabular", N, "label", ("fastavro",)),
    Fixture("sav", "survey.sav", _sav, "tabular", N, "label", ("pyreadstat",)),
    Fixture("dta", "survey.dta", _dta, "tabular", N, "label", ("pyreadstat",)),
    Fixture("npy", "images.npy", _npy, "image", N, None),
    Fixture("npz", "arrays.npz", _npz, "image", N, "y"),
    Fixture("hdf5", "arrays.h5", _hdf5, "tabular", N, "y", ("h5py",)),
    Fixture("sqlite", "data.sqlite", _sqlite, "tabular", N, "label"),
    Fixture("xml", "data.xml", _xml, "tabular", N, "label"),
    Fixture("zip_images", "images.zip", _img_zip, "image", 30, "folder", ("PIL",)),
    Fixture("tar_images", "images.tar", _img_tar, "image", 30, "folder", ("PIL",)),
    Fixture("tgz_images", "images.tgz", _img_tgz, "image", 30, "folder", ("PIL",)),
    Fixture("7z_images", "images.7z", _img_7z, "image", 30, "folder", ("PIL", "py7zr")),
    Fixture("coco", "coco.zip", _coco, "image", 30, "coco:annotations/instances.json", ("PIL",)),
    Fixture("yolo", "yolo.zip", _yolo, "image", 30, "yolo:labels/*.txt", ("PIL", "yaml")),
    Fixture("voc", "voc.zip", _voc, "image", 30, "voc:annotation/object/name", ("PIL",)),
    Fixture("image_manifest", "imgs.zip", _img_manifest, "image", 30, "labels.csv:label", ("PIL",)),
    Fixture("audio", "speech.zip", _audio_zip, "audio", 24, "folder", ("soundfile",), n_classes=2),
    Fixture("text_corpus", "reviews.zip", _text_corpus, "text", 24, "folder", n_classes=2),
    Fixture("conll", "ner.conll", _conll, "text", 30, None),
    Fixture("cifar", "cifar-10-binary.zip", _cifar, "image", 42, "label_byte"),
    Fixture("idx", "mnist.zip", _mnist, "image", 40, "idx_labels"),
    Fixture("hf", "hf_dataset.zip", _hf, "text", N, "label", ("pyarrow",), n_classes=2),
    Fixture("pickle", "model.pkl", _pickle, "mixed", 0, None),
]
BY_NAME = {f.name: f for f in FIXTURES}


def build(fx: Fixture, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    target = out_dir / fx.filename
    fx.build(target)
    return target


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "corpus_out")
    for fx in FIXTURES:
        try:
            print(fx.name, build(fx, out))
        except ImportError as exc:
            print(fx.name, "SKIPPED:", exc)
