"""Scientific arrays: ``.npy``, ``.npz``, HDF5 (``.h5/.hdf5``, MATLAB v7.3 ``.mat``).

* ``np.load(..., allow_pickle=False)`` always; object arrays are listed but not selectable.
* The user maps arrays to X (``selection.container``) and y (``selection.y_array``);
  defaults come from conventional names (``x, X, data, images, ...`` / ``y, labels, ...``).
* Shape decides modality: (N,H,W,C) / (N,C,H,W) / (N,H,W) are images, 2-D is tabular,
  other ranks are flattened to tabular when small enough.
"""

from __future__ import annotations

import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from poisonlens.adapters.base import LoadResult, Source
from poisonlens.adapters.fileset import (
    ArrayImageWriter,
    array_rows,
    image_layout,
    profile_from_rows,
    to_uint8_nhwc,
    write_rows,
)
from poisonlens.adapters.profile import normalize_label
from poisonlens.adapters.table_base import Chunk, TableAdapter, merge_selection
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import ContainerInfo, DatasetProfile, Modality, Selection

X_NAMES = ("x", "data", "features", "images", "inputs", "x_train", "train_x", "imgs", "samples")
Y_NAMES = ("y", "labels", "label", "targets", "target", "y_train", "train_y", "classes")
MAX_FLAT_FEATURES = 4096


@dataclass
class ArrayInfo:
    name: str
    shape: tuple[int, ...]
    dtype: str
    loadable: bool
    note: str = ""


class _Store:
    """Uniform lazy access to the arrays in one file."""

    def __init__(self, src: Source):
        self.src = src
        self.kind = src.kind
        self._npz: Any = None
        self._h5: Any = None

    def __enter__(self) -> _Store:
        path = os_path(self.src.path)
        if self.kind == "npz":
            self._npz = np.load(path, allow_pickle=False)
        elif self.kind == "hdf5":
            try:
                import h5py
            except ImportError as exc:
                raise UnsupportedFormatError("HDF5 files need the optional 'h5py' package") from exc
            self._h5 = h5py.File(path, "r")
        return self

    def __exit__(self, *exc: object) -> None:
        if self._npz is not None:
            self._npz.close()
        if self._h5 is not None:
            self._h5.close()

    def infos(self) -> list[ArrayInfo]:
        path = os_path(self.src.path)
        out: list[ArrayInfo] = []
        if self.kind == "npy":
            with open(path, "rb") as fh:
                shape, _fortran, dtype = _npy_header(fh)  # header only, never the data
            out.append(_info("array", shape, dtype))
        elif self.kind == "npz":
            with zipfile.ZipFile(path) as zf:
                for member in zf.namelist():
                    with zf.open(member) as member_fh:
                        shape, _f, dtype = _npy_header(member_fh)
                    out.append(_info(member[:-4] if member.endswith(".npy") else member, shape, dtype))
        elif self.kind == "hdf5":

            def visit(name: str, obj: Any) -> None:
                if hasattr(obj, "shape") and hasattr(obj, "dtype"):
                    out.append(_info(name, tuple(obj.shape), obj.dtype))

            self._h5.visititems(visit)
        return out

    def read(self, name: str, sl: slice | None = None) -> np.ndarray:
        if self.kind == "npy":
            arr = np.load(os_path(self.src.path), allow_pickle=False, mmap_mode="r")
        elif self.kind == "npz":
            arr = self._npz[name]
        else:
            arr = self._h5[name]
        return np.asarray(arr[sl] if sl is not None else arr[()])


def _npy_header(fh: Any) -> tuple[tuple[int, ...], bool, np.dtype]:
    version = np.lib.format.read_magic(fh)
    if version == (1, 0):
        return np.lib.format.read_array_header_1_0(fh)
    return np.lib.format.read_array_header_2_0(fh)


def _info(name: str, shape: tuple[int, ...], dtype: Any) -> ArrayInfo:
    dt = np.dtype(dtype)
    bad = dt.hasobject or dt.kind in ("V", "O")
    return ArrayInfo(
        name=name,
        shape=tuple(int(s) for s in shape),
        dtype=str(dt),
        loadable=not bad,
        note="object/compound dtype: not loaded (would require pickle)" if bad else "",
    )


@contextmanager
def _store(src: Source) -> Iterator[_Store]:
    with _Store(src) as s:
        yield s


def _pick(infos: list[ArrayInfo], names: tuple[str, ...], pred: Any) -> ArrayInfo | None:
    ok = [i for i in infos if i.loadable and pred(i)]
    for wanted in names:
        for i in ok:
            if i.name.rsplit("/", 1)[-1].lower() == wanted:
                return i
    return ok[0] if ok else None


class ArrayAdapter(TableAdapter):
    name = "arrays"
    specificity = 2

    def can_handle(self, src: Source) -> float:
        if src.is_dir:
            return 0.0
        return 1.0 if src.kind in ("npy", "npz", "hdf5") else 0.0

    def format_name(self, src: Source) -> str:
        return src.ext if src.ext in ("npy", "npz", "h5", "hdf5", "mat") else src.kind

    def containers(self, src: Source, cfg: ScanConfig) -> list[ContainerInfo]:
        with _store(src) as s:
            return [
                ContainerInfo(
                    name=i.name,
                    kind="array",
                    n_records=i.shape[0] if i.shape else 0,
                    shape=list(i.shape),
                    dtype=i.dtype,
                    selectable=i.loadable,
                    note=i.note,
                )
                for i in s.infos()
            ]

    def _resolve(self, src: Source, sel: Selection) -> tuple[ArrayInfo, ArrayInfo | None]:
        with _store(src) as s:
            infos = s.infos()
        by = {i.name: i for i in infos}
        if sel.container is not None:
            x = by.get(sel.container)
            if x is None or not x.loadable:
                raise UnsupportedFormatError(f"array {sel.container!r} is missing or not loadable")
        else:
            x = _pick(infos, X_NAMES, lambda i: len(i.shape) >= 2)
            if x is None:
                x = _pick(infos, X_NAMES, lambda i: len(i.shape) == 1)
            if x is None:
                raise UnsupportedFormatError("no loadable array found (object arrays are never unpickled)")
        n = x.shape[0]
        y_name = sel.y_array
        if y_name is not None:
            y = by.get(y_name)
            if y is None or not y.loadable or y.shape[:1] != (n,):
                raise UnsupportedFormatError(f"y array {y_name!r} must be loadable with length {n}")
        else:
            y = _pick(infos, Y_NAMES, lambda i: len(i.shape) == 1 and i.shape[0] == n and i.name != x.name)
        return x, y

    def default_selection(self, src: Source, containers: list[ContainerInfo], cfg: ScanConfig) -> Selection:
        x, y = self._resolve(src, Selection())
        return Selection(container=x.name, y_array=y.name if y else None, label_column=_ycol(y))

    # ---------------------------------------------------------------- tabular arrays

    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        x, y = self._resolve(src, selection)
        n = x.shape[0]
        width = int(np.prod(x.shape[1:])) if len(x.shape) > 1 else 1
        if width > MAX_FLAT_FEATURES:
            raise UnsupportedFormatError(f"array {x.name} has {width} features per record; too wide for tabular")
        with _store(src) as s:
            for start in range(0, n, chunk_rows):
                sl = slice(start, min(n, start + chunk_rows))
                block = s.read(x.name, sl).reshape(sl.stop - sl.start, width)
                df = pd.DataFrame(block, columns=[f"f{j}" for j in range(width)])
                if y is not None:
                    df[_ycol(y)] = s.read(y.name, sl)
                yield Chunk(df, src.ref(), x.name, start)

    # ---------------------------------------------------------------- image arrays

    def _labels(self, src: Source, y: ArrayInfo | None) -> list[str | None]:
        if y is None:
            return []
        with _store(src) as s:
            values = s.read(y.name)
        return [normalize_label(v.item() if hasattr(v, "item") else v) for v in values]

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        containers = self.containers(src, cfg)
        sel = merge_selection(self.default_selection(src, containers, cfg), selection)
        x, y = self._resolve(src, sel)
        layout = image_layout(x.shape)
        if layout is None:
            prof = super().inspect(src, cfg, sel)
            return prof.model_copy(update={"containers": containers})
        from poisonlens.adapters.fileset import RecordRow

        labels = self._labels(src, y)
        n = x.shape[0]
        rows = [
            RecordRow(source_file=src.ref(), payload_ref=f"array:{i}", label_raw=lbl) for i, lbl in enumerate(labels)
        ]
        return profile_from_rows(
            rows,
            n_records=n,
            fmt=self.format_name(src),
            adapter=self.name,
            modality=Modality.IMAGE,
            label_source=_ycol(y),
            label_reason=f"array '{y.name}' with length {n}" if y else "",
            cfg=cfg,
            containers=containers,
            selection=sel,
        )

    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        sel = merge_selection(profile.selection, selection)
        x, y = self._resolve(src, sel)
        layout = image_layout(x.shape)
        if layout is None:
            return super().load(src, profile, sel, canonical, cfg)
        n = x.shape[0]
        if layout == "nhwc":
            h, w, c = x.shape[1], x.shape[2], x.shape[3]
        elif layout == "nchw":
            c, h, w = x.shape[1], x.shape[2], x.shape[3]
        else:
            h, w, c = x.shape[1], x.shape[2], 1
        writer = ArrayImageWriter(canonical, n, h, w, c)
        step = max(1, cfg.inspect.chunk_rows // 10)
        with _store(src) as s:
            for start in range(0, n, step):
                sl = slice(start, min(n, start + step))
                writer.write(start, to_uint8_nhwc(s.read(x.name, sl), layout))
        writer.close()
        labels = self._labels(src, y)
        return write_rows(canonical, array_rows(n, labels, source_file=src.ref(), h=h, w=w))


def _ycol(y: ArrayInfo | None) -> str | None:
    return y.name.rsplit("/", 1)[-1] if y is not None else None
