"""Statistical packages: SPSS ``.sav``, Stata ``.dta``, SAS ``.sas7bdat`` via pyreadstat.

Value labels are applied, so a coded label column ``1, 2`` arrives as ``"cat", "dog"``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

from poisonlens.adapters.base import Source
from poisonlens.adapters.table_base import Chunk, TableAdapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import Selection

KINDS = {"sav", "dta", "sas7bdat"}


def _reader(kind: str) -> Callable[..., Any]:
    try:
        import pyreadstat
    except ImportError as exc:
        raise UnsupportedFormatError("statistical-package formats need the optional 'pyreadstat' package") from exc
    readers: dict[str, Callable[..., Any]] = {
        "sav": pyreadstat.read_sav,
        "dta": pyreadstat.read_dta,
        "sas7bdat": pyreadstat.read_sas7bdat,
    }
    return readers[kind]


class StatPackageAdapter(TableAdapter):
    name = "statpkg"
    specificity = 2

    def can_handle(self, src: Source) -> float:
        if src.is_dir:
            return 0.0
        if src.kind in KINDS:
            return 1.0
        return 0.8 if src.ext == "dta" and src.kind == "unknown" else 0.0  # old binary .dta has no magic

    def _kind(self, src: Source) -> str:
        return src.kind if src.kind in KINDS else src.ext

    def format_name(self, src: Source) -> str:
        return self._kind(src)

    def count_records(self, src: Source, selection: Selection, cfg: ScanConfig) -> int | None:
        _, meta = _reader(self._kind(src))(os_path(src.path), metadataonly=True)
        n = getattr(meta, "number_rows", None)
        return int(n) if n is not None and n >= 0 else None

    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        import pyreadstat

        read = _reader(self._kind(src))
        row = 0
        for df, _meta in pyreadstat.read_file_in_chunks(
            read, os_path(src.path), chunksize=chunk_rows, apply_value_formats=True, formats_as_category=False
        ):
            yield Chunk(df, src.ref(), None, row)
            row += len(df)
