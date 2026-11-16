"""Shared helpers for datasets whose records are files or array slices, not table rows
(image / audio / text-document sets, NumPy / IDX / CIFAR / HF image arrays)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from poisonlens.adapters.base import LoadResult, ManifestWriter, record_id, sha256_file
from poisonlens.adapters.profile import capabilities
from poisonlens.core.config import ScanConfig
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import (
    ContainerInfo,
    DatasetProfile,
    LabelCandidate,
    Modality,
    Selection,
    SplitInfo,
)

ARRAY_IMAGES = "array_images.npy"


@dataclass
class RecordRow:
    source_file: str
    payload_ref: str
    label_raw: str | None = None
    split: str | None = None
    width: int | None = None
    height: int | None = None
    row: int | None = None
    offset: int | None = None


def profile_from_rows(
    rows: list[RecordRow],
    *,
    n_records: int,
    fmt: str,
    adapter: str,
    modality: Modality,
    label_source: str | None,
    label_reason: str,
    cfg: ScanConfig,
    containers: list[ContainerInfo] | None = None,
    selection: Selection | None = None,
    warnings: list[str] | None = None,
    sampled: bool = False,
) -> DatasetProfile:
    hist = Counter(r.label_raw for r in rows if r.label_raw is not None)
    label = label_source if hist else None
    splits = Counter(r.split for r in rows if r.split)
    cands = [LabelCandidate(column=label_source, score=1.0, reason=label_reason)] if label and label_source else []
    return DatasetProfile(
        format=fmt,
        modality=modality,
        n_records=n_records,
        label_candidates=cands,
        label_chosen=label,
        splits=SplitInfo(column="path", counts=dict(splits)) if splits else None,
        class_hist={k: hist[k] for k in sorted(hist)},
        capabilities=capabilities(modality=modality, n_records=n_records, label=label, n_classes=len(hist), cfg=cfg),
        adapter=adapter,
        containers=containers or [],
        selection=(selection or Selection()).model_copy(update={"label_column": label}),
        sampled=sampled,
        warnings=warnings or [],
    )


def write_rows(canonical: Path, rows: Iterable[RecordRow], batch: int = 50_000) -> LoadResult:
    mw = ManifestWriter(canonical)
    buf: list[RecordRow] = []
    i = 0

    def flush() -> None:
        nonlocal i, buf
        if not buf:
            return
        mw.append(
            {
                "record_id": [record_id(i + k) for k in range(len(buf))],
                "source_file": [r.source_file for r in buf],
                "row": [r.row for r in buf],
                "offset": [r.offset for r in buf],
                "split": [r.split for r in buf],
                "label_raw": [r.label_raw for r in buf],
                "payload_ref": [r.payload_ref for r in buf],
                "width": [r.width for r in buf],
                "height": [r.height for r in buf],
            }
        )
        i += len(buf)
        buf = []

    for r in rows:
        buf.append(r)
        if len(buf) >= batch:
            flush()
    flush()
    manifest, label_names = mw.finish()
    artifacts = {"manifest.parquet": sha256_file(manifest)}
    arr = canonical / ARRAY_IMAGES
    if arr.exists():
        artifacts[ARRAY_IMAGES] = sha256_file(arr)
    return LoadResult(
        n_records=mw.n,
        label_names=label_names,
        class_hist={k: mw.labels[k] for k in label_names},
        split_counts=dict(mw.splits),
        artifacts=artifacts,
    )


# --------------------------------------------------------------------------- array images


def to_uint8_nhwc(block: np.ndarray, layout: str) -> np.ndarray:
    """Convert an image block to uint8 NHWC. ``layout`` is "nhwc", "nchw" or "nhw"."""
    a = np.asarray(block)
    if layout == "nchw":
        a = a.transpose(0, 2, 3, 1)
    elif layout == "nhw":
        a = a[..., None]
    if a.dtype == np.uint8:
        return np.ascontiguousarray(a)
    a = a.astype(np.float64)
    if a.size and np.nanmax(a) <= 1.0 and np.nanmin(a) >= 0.0:
        a = a * 255.0
    return np.clip(np.nan_to_num(a), 0, 255).astype(np.uint8)


def image_layout(shape: tuple[int, ...]) -> str | None:
    """Recognize image arrays by shape: (N,H,W,C), (N,C,H,W) or (N,H,W)."""
    if len(shape) == 4:
        _, a, b, c = shape
        if c in (1, 3, 4) and a >= 8 and b >= 8:
            return "nhwc"
        if a in (1, 3) and b >= 8 and c >= 8:
            return "nchw"
    if len(shape) == 3:
        _, h, w = shape
        if h >= 8 and w >= 8:
            return "nhw"
    return None


class ArrayImageWriter:
    """Writes images held in arrays to ``canonical/array_images.npy`` (uint8 NHWC memmap)."""

    def __init__(self, canonical: Path, n: int, h: int, w: int, c: int):
        canonical.mkdir(parents=True, exist_ok=True)
        self.path = canonical / ARRAY_IMAGES
        self.arr = np.lib.format.open_memmap(os_path(self.path), mode="w+", dtype=np.uint8, shape=(n, h, w, c))

    def write(self, start: int, block: np.ndarray) -> None:
        self.arr[start : start + len(block)] = block

    def close(self) -> None:
        self.arr.flush()
        del self.arr


def array_rows(
    n: int,
    labels: Iterator[str | None] | list[str | None],
    *,
    source_file: str,
    h: int,
    w: int,
    splits: list[str | None] | None = None,
) -> Iterator[RecordRow]:
    label_list = list(labels)
    for i in range(n):
        yield RecordRow(
            source_file=source_file,
            payload_ref=f"array:{i}",
            label_raw=label_list[i] if i < len(label_list) else None,
            split=splits[i] if splits else None,
            width=w,
            height=h,
            offset=i,
        )
