"""ML-native dataset formats, detected by structure.

* **CIFAR binary batches** (``data_batch_*.bin``, ``test_batch.bin``): records of
  1 label byte (CIFAR-10) or 2 (CIFAR-100: coarse, fine) + 3072 pixel bytes. Class names
  from ``batches.meta.txt`` / ``fine_label_names.txt``. The *python* CIFAR version is a
  pickle and is therefore scan-only (serialized adapter).
* **MNIST IDX** (``*-images-idx3-ubyte`` + ``*-labels-idx1-ubyte``): big-endian header,
  images paired with labels of equal length by name prefix (``train``, ``t10k``).
* **Hugging Face ``datasets`` directories** (``dataset_info.json`` + Arrow stream files,
  optionally one sub-directory per split): ``ClassLabel`` names become label names;
  ``Image`` features (struct of bytes/path) are written to ``canonical/payloads/``.

TFRecord is not supported yet (see docs/MIGRATION_NOTES.md).
"""

from __future__ import annotations

import json
import struct
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import numpy as np
import pyarrow as pa

from poisonlens.adapters.base import DatasetAdapter, LoadResult, Source, member_ext, record_id, split_from_path
from poisonlens.adapters.fileset import (
    ArrayImageWriter,
    RecordRow,
    array_rows,
    profile_from_rows,
    to_uint8_nhwc,
    write_rows,
)
from poisonlens.adapters.profile import normalize_label
from poisonlens.adapters.table_base import Chunk, TableAdapter, merge_selection
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import DatasetProfile, Modality, Selection

CIFAR_PIXELS = 3072


# --------------------------------------------------------------------------- CIFAR binary


class CifarBinaryAdapter(DatasetAdapter):
    name = "cifar_binary"
    specificity = 8

    def _batches(self, src: Source) -> list[tuple[str, int]]:
        """(member, label bytes) for every batch file."""
        out = []
        cands = src.members() if src.is_dir else [None]
        for rel in cands:
            path = src.member_path(rel) if rel else src.path
            base = (rel or src.name).rsplit("/", 1)[-1].lower()
            if not base.endswith(".bin") or "batch" not in base and base not in ("train.bin", "test.bin"):
                continue
            size = path.stat().st_size
            if size and size % (CIFAR_PIXELS + 1) == 0:
                out.append((rel or "", 1))
            elif size and size % (CIFAR_PIXELS + 2) == 0:
                out.append((rel or "", 2))
        return out

    def can_handle(self, src: Source) -> float:
        return 0.95 if self._batches(src) else 0.0

    def _names(self, src: Source, label_bytes: int) -> list[str] | None:
        if not src.is_dir:
            return None
        wanted = ("batches.meta.txt",) if label_bytes == 1 else ("fine_label_names.txt",)
        for rel in src.members():
            if rel.rsplit("/", 1)[-1].lower() in wanted:
                text = src.member_path(rel).read_text(encoding="utf-8", errors="replace")
                return [ln.strip() for ln in text.splitlines() if ln.strip()]
        return None

    def _records(self, src: Source) -> Iterator[tuple[str, int, np.ndarray]]:
        """(member, label bytes, memmap of shape (n, label_bytes + 3072)) per batch."""
        for rel, lb in self._batches(src):
            path = src.member_path(rel) if rel else src.path
            raw = np.memmap(os_path(path), dtype=np.uint8, mode="r")
            yield rel, lb, raw.reshape(-1, CIFAR_PIXELS + lb)

    def _labels(self, src: Source) -> tuple[list[str | None], list[str | None], int]:
        labels: list[str | None] = []
        splits: list[str | None] = []
        lb_seen = 1
        for rel, lb, recs in self._records(src):
            lb_seen = lb
            names = self._names(src, lb)
            raw = recs[:, lb - 1]  # CIFAR-100: fine label is the second byte
            labels.extend(names[int(v)] if names and int(v) < len(names) else str(int(v)) for v in raw)
            split = "test" if "test" in (rel or src.name).lower() else "train"
            splits.extend([split] * len(raw))
        return labels, splits, lb_seen

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        labels, splits, lb = self._labels(src)
        rows = [
            RecordRow(source_file="", payload_ref="", label_raw=lab, split=sp)
            for lab, sp in zip(labels, splits, strict=True)
        ]
        return profile_from_rows(
            rows,
            n_records=len(rows),
            fmt="cifar_binary",
            adapter=self.name,
            modality=Modality.IMAGE,
            label_source="label_byte",
            label_reason=f"CIFAR-{10 if lb == 1 else 100} label byte",
            cfg=cfg,
            selection=merge_selection(Selection(), selection),
        )

    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        labels, splits, _ = self._labels(src)
        n = len(labels)
        writer = ArrayImageWriter(canonical, n, 32, 32, 3)
        start = 0
        sources: list[str] = []
        for rel, lb, recs in self._records(src):
            imgs = recs[:, lb:].reshape(-1, 3, 32, 32)
            writer.write(start, to_uint8_nhwc(imgs, "nchw"))
            start += len(imgs)
            sources.extend([src.ref(rel) if rel else src.ref()] * len(imgs))
        writer.close()

        def rows() -> Iterator[RecordRow]:
            for r, src_file in zip(
                array_rows(n, labels, source_file="", h=32, w=32, splits=splits), sources, strict=True
            ):
                r.source_file = src_file
                yield r

        return write_rows(canonical, rows())


# --------------------------------------------------------------------------- MNIST IDX

_IDX_DTYPES = {0x08: ">u1", 0x09: ">i1", 0x0B: ">i2", 0x0C: ">i4", 0x0D: ">f4", 0x0E: ">f8"}


def idx_header(path: Path) -> tuple[np.dtype, tuple[int, ...], int] | None:
    with open(os_path(path), "rb") as fh:
        head = fh.read(4)
        if len(head) < 4 or head[0] != 0 or head[1] != 0 or head[2] not in _IDX_DTYPES or not 1 <= head[3] <= 4:
            return None
        ndim = head[3]
        dims = struct.unpack(">" + "I" * ndim, fh.read(4 * ndim))
    dtype = np.dtype(_IDX_DTYPES[head[2]])
    offset = 4 + 4 * ndim
    expected = offset + int(np.prod(dims)) * dtype.itemsize
    if path.stat().st_size != expected:
        return None
    return dtype, tuple(int(d) for d in dims), offset


class IdxAdapter(DatasetAdapter):
    name = "mnist_idx"
    specificity = 8

    def _files(self, src: Source) -> dict[str, tuple[np.dtype, tuple[int, ...], int, Path]]:
        out = {}
        for rel in src.members() if src.is_dir else [""]:
            path = src.member_path(rel) if rel else src.path
            hdr = idx_header(path)
            if hdr is not None:
                out[rel or src.name] = (*hdr, path)
        return out

    def _pairs(self, src: Source) -> list[tuple[str, str | None]]:
        files = self._files(src)
        images = [k for k, v in files.items() if len(v[1]) == 3]
        labels = [k for k, v in files.items() if len(v[1]) == 1]
        pairs = []
        for img in sorted(images):
            prefix = img.rsplit("/", 1)[-1].split("-")[0].lower()
            n = files[img][1][0]
            match = next(
                (lb for lb in labels if lb.rsplit("/", 1)[-1].lower().startswith(prefix) and files[lb][1][0] == n),
                None,
            )
            pairs.append((img, match))
        return pairs

    def can_handle(self, src: Source) -> float:
        return 0.95 if self._pairs(src) else 0.0

    def _read(self, src: Source, name: str) -> np.ndarray:
        dtype, dims, offset, path = self._files(src)[name]
        return np.memmap(os_path(path), dtype=dtype, mode="r", offset=offset, shape=dims)

    def _labels(self, src: Source) -> tuple[list[str | None], list[str | None], list[tuple[str, int]]]:
        labels: list[str | None] = []
        splits: list[str | None] = []
        parts = []
        for img, lab in self._pairs(src):
            n = self._files(src)[img][1][0]
            if lab:
                labels.extend(str(int(v)) for v in self._read(src, lab))
            else:
                labels.extend([None] * n)
            splits.extend([split_from_path(img.rsplit("/", 1)[-1])] * n)
            parts.append((img, n))
        return labels, splits, parts

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        labels, splits, _ = self._labels(src)
        rows = [
            RecordRow(source_file="", payload_ref="", label_raw=lab, split=sp)
            for lab, sp in zip(labels, splits, strict=True)
        ]
        return profile_from_rows(
            rows,
            n_records=len(rows),
            fmt="mnist_idx",
            adapter=self.name,
            modality=Modality.IMAGE,
            label_source="idx_labels",
            label_reason="paired *-labels-idx1-ubyte file",
            cfg=cfg,
            selection=merge_selection(Selection(), selection),
        )

    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        labels, splits, parts = self._labels(src)
        shapes = {self._files(src)[img][1][1:] for img, _ in parts}
        if len(shapes) != 1:
            raise UnsupportedFormatError("IDX image files have different image sizes")
        h, w = next(iter(shapes))
        writer = ArrayImageWriter(canonical, len(labels), h, w, 1)
        start = 0
        sources: list[str] = []
        for img, n in parts:
            writer.write(start, to_uint8_nhwc(self._read(src, img), "nhw"))
            start += n
            sources.extend([src.ref(img) if src.is_dir else src.ref()] * n)
        writer.close()

        def rows() -> Iterator[RecordRow]:
            for r, s in zip(
                array_rows(len(labels), labels, source_file="", h=h, w=w, splits=splits), sources, strict=True
            ):
                r.source_file = s
                yield r

        return write_rows(canonical, rows())


# --------------------------------------------------------------------------- Hugging Face datasets


def _read_arrow(path: Path) -> pa.Table:
    with pa.memory_map(os_path(path)) as mm:
        try:
            return pa.ipc.open_stream(mm).read_all()
        except pa.ArrowInvalid:
            mm.seek(0)
            return pa.ipc.open_file(mm).read_all()


class HFDatasetAdapter(TableAdapter):
    name = "hf_dataset"
    specificity = 9

    def _splits(self, src: Source) -> list[tuple[str | None, list[str], dict[str, Any]]]:
        """(split name, arrow members, features) for every dataset_info.json found."""
        out = []
        for rel in src.members():
            if rel.rsplit("/", 1)[-1] != "dataset_info.json":
                continue
            folder = rel.rsplit("/", 1)[0] if "/" in rel else ""
            arrows = [
                m
                for m in src.members()
                if member_ext(m) == "arrow" and (m.rsplit("/", 1)[0] if "/" in m else "") == folder
            ]
            if not arrows:
                continue
            try:
                info = json.loads(src.member_path(rel).read_text(encoding="utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            split = folder.rsplit("/", 1)[-1] if folder else None
            out.append((split, sorted(arrows), info.get("features") or {}))
        return out

    def can_handle(self, src: Source) -> float:
        return 0.97 if src.is_dir and self._splits(src) else 0.0

    def format_name(self, src: Source) -> str:
        return "hf_dataset"

    @staticmethod
    def _class_names(features: dict[str, Any]) -> dict[str, list[str]]:
        return {
            k: [str(n) for n in v.get("names", [])]
            for k, v in features.items()
            if isinstance(v, dict) and v.get("_type") == "ClassLabel"
        }

    @staticmethod
    def _image_columns(features: dict[str, Any]) -> list[str]:
        return [k for k, v in features.items() if isinstance(v, dict) and v.get("_type") == "Image"]

    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        for split, arrows, features in self._splits(src):
            names = self._class_names(features)
            images = set(self._image_columns(features))
            row = 0
            for rel in arrows:
                table = _read_arrow(src.member_path(rel))
                keep = [c for c in table.column_names if c not in images]
                for off in range(0, table.num_rows, chunk_rows):
                    df = table.select(keep).slice(off, chunk_rows).to_pandas()
                    for col, labels in names.items():
                        if col in df.columns:
                            df[col] = df[col].map(
                                lambda v, lab=labels: lab[int(v)] if 0 <= int(v) < len(lab) else str(v)
                            )
                    if split is not None and "split" not in df.columns:
                        df["split"] = split
                    yield Chunk(df, src.ref(rel), split, row)
                    row += len(df)

    def default_selection(self, src: Source, containers: list[Any], cfg: ScanConfig) -> Selection:
        for _split, _arrows, features in self._splits(src):
            names = self._class_names(features)
            if names:
                return Selection(label_column=next(iter(names)))
        return Selection()

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        prof = super().inspect(src, cfg, selection)
        if any(self._image_columns(f) for _s, _a, f in self._splits(src)):
            prof = prof.model_copy(update={"modality": Modality.IMAGE})
        return prof

    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        image_cols = [c for _s, _a, f in self._splits(src) for c in self._image_columns(f)]
        if not image_cols:
            return super().load(src, profile, selection, canonical, cfg)
        # Image datasets: write each image's bytes to canonical/payloads/ and reference it.
        payloads = canonical / "payloads"
        payloads.mkdir(parents=True, exist_ok=True)
        label = merge_selection(profile.selection, selection).label_column
        rows: list[RecordRow] = []
        i = 0
        for split, arrows, features in self._splits(src):
            names = self._class_names(features)
            img_col = self._image_columns(features)[0]
            for rel in arrows:
                table = _read_arrow(src.member_path(rel))
                for rec in table.to_pylist():
                    img = rec.get(img_col) or {}
                    data = img.get("bytes") if isinstance(img, dict) else None
                    if not data:
                        continue
                    target = payloads / f"{record_id(i)}.img"
                    target.write_bytes(data)
                    raw = rec.get(label) if label else None
                    if label in names and raw is not None:
                        raw = names[label][int(raw)] if 0 <= int(raw) < len(names[label]) else raw
                    rows.append(
                        RecordRow(
                            source_file=src.ref(rel),
                            payload_ref=f"canonical/payloads/{target.name}",
                            label_raw=normalize_label(raw),
                            split=split,
                        )
                    )
                    i += 1
        return write_rows(canonical, rows)


__all__ = ["CifarBinaryAdapter", "HFDatasetAdapter", "IdxAdapter"]
