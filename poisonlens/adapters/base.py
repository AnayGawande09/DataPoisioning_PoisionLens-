"""Adapter contract and the Canonical Dataset Representation (CDR) writer.

CDR on disk (``canonical/``):

* ``manifest.parquet`` — one row per record: ``record_id, source_file, sheet, row, offset,
  split, label_raw, label_idx, payload_ref`` (+ optional ``width, height`` for images).
* ``features_raw.parquet`` — tabular / text-in-column data, keyed by ``record_id``.
* image/audio/blob-text payloads stay as files; ``payload_ref`` is ``sandbox/<path>`` or
  ``upload/<file>``. Images that only exist inside arrays (NumPy, IDX, CIFAR, HF) are
  written once to ``canonical/array_images.npy`` and referenced as ``array:<i>``.
* ``profile.json`` — the :class:`DatasetProfile`.

Every adapter streams: tables are read in chunks twice (pass 1 infers a stable column
type over the whole file, pass 2 writes Parquet with that schema), so memory stays
bounded by the chunk size and a column that changes type mid-file never breaks the schema.
"""

from __future__ import annotations

import hashlib
import json
import math
from abc import ABC, abstractmethod
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from poisonlens.core.config import ScanConfig
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import DatasetProfile, Selection
from poisonlens.ingest.upload import stored_extension

MANIFEST_SCHEMA = pa.schema(
    [
        ("record_id", pa.string()),
        ("source_file", pa.string()),
        ("sheet", pa.string()),
        ("row", pa.int64()),
        ("offset", pa.int64()),
        ("split", pa.string()),
        ("label_raw", pa.string()),
        ("label_idx", pa.int32()),
        ("payload_ref", pa.string()),
        ("width", pa.int32()),
        ("height", pa.int32()),
    ]
)
SPLIT_VOCAB = {
    "train": "train",
    "training": "train",
    "val": "val",
    "valid": "val",
    "validation": "val",
    "dev": "val",
    "test": "test",
    "testing": "test",
    "t10k": "test",
}


def record_id(i: int) -> str:
    return f"r{i:09d}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(os_path(path), "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


# --------------------------------------------------------------------------- source


@dataclass
class Source:
    """What an adapter reads: one file, or a directory of extracted archive members."""

    path: Path
    kind: str  # sniffed kind of a file, or "directory"
    name: str  # original upload name (extension hint)
    payload_prefix: str = "upload"  # how payload_refs are rooted: "upload" or "sandbox"
    self_ref: str | None = None  # payload_ref of a file source (e.g. "sandbox/data/train.csv")
    _members: list[str] | None = field(default=None, repr=False)

    @property
    def ext(self) -> str:
        return stored_extension(self.name)

    @property
    def is_dir(self) -> bool:
        return self.kind == "directory"

    def members(self) -> list[str]:
        """Posix paths of regular files under a directory source (sorted, cached)."""
        if not self.is_dir:
            return []
        if self._members is None:
            root = Path(os_path(self.path))
            self._members = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
        return self._members

    def member_path(self, rel: str) -> Path:
        return self.path / rel

    def ref(self, rel: str | None = None) -> str:
        """payload_ref for a member (directory) or for the source file itself."""
        if rel is None:
            return self.self_ref or f"{self.payload_prefix}/{self.path.name}"
        return f"{self.payload_prefix}/{rel}"


def member_ext(rel: str) -> str:
    return stored_extension(rel.rsplit("/", 1)[-1])


def split_from_path(rel: str) -> str | None:
    for part in rel.lower().split("/")[:-1]:
        if part in SPLIT_VOCAB:
            return SPLIT_VOCAB[part]
    stem = rel.lower().rsplit("/", 1)[-1]
    for prefix, split in (("train", "train"), ("t10k", "test"), ("test", "test"), ("val", "val")):
        if stem.startswith(prefix):
            return split
    return None


# --------------------------------------------------------------------------- results


@dataclass
class LoadResult:
    n_records: int
    label_names: list[str]
    class_hist: dict[str, int]
    split_counts: dict[str, int]
    artifacts: dict[str, str]  # canonical-relative name -> sha256
    warnings: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- type inference


_KIND_ORDER = ["null", "bool", "int", "float", "datetime", "string"]


def _merge_kind(a: str, b: str) -> str:
    if a == b or b == "null":
        return a
    if a == "null":
        return b
    if {a, b} <= {"int", "float"}:
        return "float"
    if {a, b} <= {"bool", "int"}:
        return "int"
    return "string"


def _series_kind(s: pd.Series, *, parse_strings: bool) -> str:
    s = s.dropna()
    if s.empty:
        return "null"
    if pd.api.types.is_bool_dtype(s.dtype):
        return "bool"
    if pd.api.types.is_integer_dtype(s.dtype):
        return "int"
    if pd.api.types.is_float_dtype(s.dtype):
        return "int" if np.all(np.mod(s.to_numpy(dtype=float), 1) == 0) and s.abs().max() < 2**53 else "float"
    if pd.api.types.is_datetime64_any_dtype(s.dtype):
        return "datetime"
    inferred = pd.api.types.infer_dtype(s, skipna=True)
    if inferred == "boolean":
        return "bool"
    if inferred == "integer":
        return "int"
    if inferred in ("floating", "mixed-integer-float", "decimal"):
        return "float"
    if inferred in ("datetime", "datetime64", "date"):
        return "datetime"
    if inferred == "string" and parse_strings:
        stripped = s.astype(str).str.strip()
        nums = pd.to_numeric(stripped, errors="coerce")
        if nums.notna().all():
            ints = stripped.str.fullmatch(r"[+-]?\d+")
            return "int" if ints.all() else "float"
        lowered = stripped.str.lower()
        if lowered.isin(["true", "false"]).all():
            return "bool"
    return "string"


def infer_kinds(chunks: Iterator[pd.DataFrame], *, parse_strings: bool) -> tuple[dict[str, str], int]:
    """Pass 1: stable kind per column over all chunks, plus total row count."""
    kinds: dict[str, str] = {}
    n = 0
    for df in chunks:
        n += len(df)
        for col in df.columns:
            k = _series_kind(df[col], parse_strings=parse_strings)
            kinds[col] = _merge_kind(kinds.get(col, "null"), k)
    return kinds, n


_ARROW_TYPES = {
    "null": pa.string(),
    "bool": pa.bool_(),
    "int": pa.int64(),
    "float": pa.float64(),
    "datetime": pa.timestamp("us"),
    "string": pa.string(),
}


def _texty(s: pd.Series) -> bool:
    """object, pandas "string" or pandas 3 "str" dtype."""
    return s.dtype == object or pd.api.types.is_string_dtype(s.dtype)


def cast_frame(df: pd.DataFrame, kinds: dict[str, str]) -> pa.Table:
    """Pass 2: cast a chunk to the inferred schema (columns missing in this chunk become null)."""
    arrays = []
    names = []
    for col, kind in kinds.items():
        s = df[col] if col in df.columns else pd.Series([None] * len(df), dtype=object)
        if kind == "int":
            v = pd.to_numeric(s.astype("string").str.strip() if _texty(s) else s, errors="coerce")
            arr = pa.array(v.astype("Int64"), type=pa.int64(), from_pandas=True)
        elif kind == "float":
            v = pd.to_numeric(s.astype("string").str.strip() if _texty(s) else s, errors="coerce")
            arr = pa.array(v.astype("float64"), type=pa.float64(), from_pandas=True)
        elif kind == "bool":
            if not pd.api.types.is_bool_dtype(s.dtype):
                v = s.astype("string").str.strip().str.lower().map({"true": True, "false": False})
            else:
                v = s
            arr = pa.array(v.astype("boolean"), type=pa.bool_(), from_pandas=True)
        elif kind == "datetime":
            arr = pa.array(pd.to_datetime(s, errors="coerce"), type=pa.timestamp("us"), from_pandas=True)
        else:
            v = s.map(lambda x: None if x is None or (isinstance(x, float) and math.isnan(x)) else str(x))
            arr = pa.array(v, type=pa.string(), from_pandas=True)
        arrays.append(arr)
        names.append(col)
    return pa.Table.from_arrays(arrays, names=names)


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """String column names, unique, never colliding with ``record_id``."""
    seen: Counter[str] = Counter()
    out = []
    for c in df.columns:
        name = str(c).strip() or "column"
        if name == "record_id":
            name = "record_id_"
        seen[name] += 1
        out.append(name if seen[name] == 1 else f"{name}.{seen[name] - 1}")
    df = df.copy()
    df.columns = out
    return df


# --------------------------------------------------------------------------- manifest writer


class ManifestWriter:
    """Streams manifest rows; assigns ``label_idx`` once all labels are known."""

    def __init__(self, canonical: Path):
        self.canonical = canonical
        canonical.mkdir(parents=True, exist_ok=True)
        self._tmp = canonical / "manifest.partial.parquet"
        self._writer: pq.ParquetWriter | None = None
        self.n = 0
        self.labels: Counter[str] = Counter()
        self.splits: Counter[str] = Counter()

    def append(self, rows: dict[str, list[Any] | None]) -> None:
        n = len(rows["record_id"] or [])
        cols = {}
        for f in MANIFEST_SCHEMA:
            vals = rows.get(f.name)
            cols[f.name] = pa.array(vals if vals is not None else [None] * n, type=f.type)
        table = pa.table(cols, schema=MANIFEST_SCHEMA)
        if self._writer is None:
            self._writer = pq.ParquetWriter(os_path(self._tmp), MANIFEST_SCHEMA)
        self._writer.write_table(table)
        self.n += n
        self.labels.update(v for v in rows.get("label_raw") or [] if v is not None)
        self.splits.update(v for v in rows.get("split") or [] if v is not None)

    def finish(self) -> tuple[Path, list[str]]:
        if self._writer is None:
            self.append({"record_id": []})
        assert self._writer is not None  # noqa: S101 - set by append above
        self._writer.close()
        label_names = sorted(self.labels)
        index = {name: i for i, name in enumerate(label_names)}
        final = self.canonical / "manifest.parquet"
        reader = pq.ParquetFile(os_path(self._tmp))
        writer = pq.ParquetWriter(os_path(final), MANIFEST_SCHEMA)
        for batch in reader.iter_batches(batch_size=200_000):
            t = pa.Table.from_batches([batch], schema=MANIFEST_SCHEMA)
            raw = t.column("label_raw").to_pylist()
            idx = pa.array([index.get(v, -1) if v is not None else -1 for v in raw], type=pa.int32())
            t = t.set_column(MANIFEST_SCHEMA.get_field_index("label_idx"), "label_idx", idx)
            writer.write_table(t)
        writer.close()
        reader.close()
        Path(os_path(self._tmp)).unlink()
        return final, label_names


class FeatureWriter:
    """Streams ``features_raw.parquet`` (record_id + columns) with a fixed schema."""

    def __init__(self, canonical: Path, kinds: dict[str, str]):
        canonical.mkdir(parents=True, exist_ok=True)
        self.path = canonical / "features_raw.parquet"
        self.kinds = kinds
        fields = [pa.field("record_id", pa.string())] + [pa.field(c, _ARROW_TYPES[k]) for c, k in kinds.items()]
        self.schema = pa.schema(fields)
        self._writer = pq.ParquetWriter(os_path(self.path), self.schema)

    def write(self, ids: list[str], df: pd.DataFrame) -> None:
        t = cast_frame(df, self.kinds)
        t = t.add_column(0, "record_id", pa.array(ids, type=pa.string()))
        self._writer.write_table(t.cast(self.schema))

    def close(self) -> Path:
        self._writer.close()
        return self.path


# --------------------------------------------------------------------------- adapter ABC


class DatasetAdapter(ABC):
    """One family of formats. Subclasses are registered in ``adapters.registry``."""

    name: ClassVar[str]
    #: higher wins ties in the registry (e.g. "COCO image set" beats "generic directory")
    specificity: ClassVar[int] = 0

    @abstractmethod
    def can_handle(self, src: Source) -> float:
        """Confidence 0..1 that this adapter understands ``src``."""

    @abstractmethod
    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        """Cheap, sampled profile. Never reads the whole dataset into memory."""

    @abstractmethod
    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        """Stream the selected data into the CDR under ``canonical``."""

    def iter_chunks(self, src: Source, selection: Selection, chunk_rows: int) -> Iterator[pd.DataFrame]:
        """Raw record chunks (tables). File-set adapters yield manifest-shaped frames."""
        raise NotImplementedError(f"{self.name} does not stream table chunks")


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(path)
