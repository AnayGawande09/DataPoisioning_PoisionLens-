"""Spreadsheets: xlsx / xlsm (openpyxl, read-only, formulas visible), xls (xlrd), ods (odfpy).

Macros are never executed (openpyxl and xlrd cannot run VBA). Formulas are read as their
text (``data_only=False``) so F10 sees ``=HYPERLINK(...)`` rather than a cached value.
Every sheet, including hidden / very-hidden ones, is listed with its state for F08.
Default selection: all *visible* sheets whose header matches the first visible sheet.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pandas as pd

from poisonlens.adapters.base import Source
from poisonlens.adapters.table_base import Chunk, TableAdapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import ContainerInfo, Selection

_XLRD_STATE = {0: "visible", 1: "hidden", 2: "veryHidden"}


def _header(row: tuple[Any, ...]) -> list[str]:
    return [str(v).strip() if v not in (None, "") else f"column_{j}" for j, v in enumerate(row)]


def _nonempty(row: tuple[Any, ...]) -> bool:
    return any(v not in (None, "") for v in row)


class SpreadsheetAdapter(TableAdapter):
    name = "spreadsheet"
    specificity = 2

    def can_handle(self, src: Source) -> float:
        if src.is_dir:
            return 0.0
        if src.kind == "xlsx" or src.kind == "ods":
            return 1.0
        if src.kind == "ole2" and src.ext == "xls":
            return 0.95
        return 0.0

    def format_name(self, src: Source) -> str:
        return {"ods": "ods", "ole2": "xls"}.get(src.kind, src.ext if src.ext in ("xlsx", "xlsm") else "xlsx")

    # ---------------------------------------------------------------- row sources

    def _sheets(self, src: Source) -> Iterator[tuple[str, str, Iterator[tuple[Any, ...]]]]:
        """Yield (sheet name, state, row iterator) for every sheet."""
        path = os_path(src.path)
        if src.kind == "xlsx":
            import openpyxl

            wb = openpyxl.load_workbook(path, read_only=True, data_only=False, keep_links=False)
            try:
                for ws in wb.worksheets:
                    yield ws.title, ws.sheet_state, ws.iter_rows(values_only=True)
            finally:
                wb.close()
        elif src.kind == "ole2":
            import xlrd

            try:
                book = xlrd.open_workbook(path, on_demand=True)
            except xlrd.biffh.XLRDError as exc:
                raise UnsupportedFormatError(f"not a readable .xls workbook: {exc}") from exc
            try:
                for i in range(book.nsheets):
                    sh = book.sheet_by_index(i)
                    state = _XLRD_STATE.get(getattr(sh, "visibility", 0), "visible")
                    yield sh.name, state, (tuple(sh.row_values(r)) for r in range(sh.nrows))
                    book.unload_sheet(i)
            finally:
                book.release_resources()
        elif src.kind == "ods":
            frames = pd.read_excel(path, engine="odf", sheet_name=None, header=None, dtype=object)
            for name, df in frames.items():
                rows = (tuple(None if pd.isna(v) else v for v in r) for r in df.itertuples(index=False))
                yield str(name), "visible", rows
        else:
            raise UnsupportedFormatError(f"not a spreadsheet: {src.kind}")

    def containers(self, src: Source, cfg: ScanConfig) -> list[ContainerInfo]:
        out = []
        for name, state, rows in self._sheets(src):
            n = -1  # header row
            for row in rows:
                if _nonempty(row):
                    n += 1
            out.append(
                ContainerInfo(
                    name=name,
                    kind="sheet",
                    n_records=max(0, n),
                    state=state,
                    note="" if state == "visible" else "hidden sheet (not selected by default)",
                )
            )
        return out

    def _headers(self, src: Source) -> dict[str, list[str]]:
        headers = {}
        for name, _state, rows in self._sheets(src):
            for row in rows:
                if _nonempty(row):
                    headers[name] = _header(row)
                    break
        return headers

    def default_selection(self, src: Source, containers: list[ContainerInfo], cfg: ScanConfig) -> Selection:
        visible = [c.name for c in containers if c.state == "visible" and (c.n_records or 0) > 0]
        if not visible:
            visible = [c.name for c in containers if (c.n_records or 0) > 0][:1]
        if not visible:
            return Selection(sheets=[c.name for c in containers][:1])
        headers = self._headers(src)
        first = headers.get(visible[0])
        return Selection(sheets=[s for s in visible if headers.get(s) == first])

    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        wanted = selection.sheets
        for name, _state, rows in self._sheets(src):
            if wanted is not None and name not in wanted:
                continue
            header: list[str] | None = None
            buf: list[tuple[Any, ...]] = []
            row_no = 0
            for row in rows:
                if not _nonempty(row):
                    continue
                if header is None:
                    header = _header(row)
                    continue
                padded = (tuple(row) + (None,) * len(header))[: len(header)]
                buf.append(padded)
                if len(buf) >= chunk_rows:
                    yield Chunk(pd.DataFrame(buf, columns=header, dtype=object), src.ref(), name, row_no)
                    row_no += len(buf)
                    buf = []
            if header is not None and buf:
                yield Chunk(pd.DataFrame(buf, columns=header, dtype=object), src.ref(), name, row_no)
