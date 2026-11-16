"""SQLite databases, opened read-only and immutable with a deny-by-default authorizer.

Only ``SELECT``, column ``READ`` and the ``count`` function are permitted; every other
action (writes, ``ATTACH``, ``PRAGMA``, ``load_extension`` and any other function) is
denied by SQLite itself. Extension loading is also switched off on the connection. Virtual
tables are listed but not selectable (reading them runs module code; F11 reports them).
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pandas as pd

from poisonlens.adapters.base import Source
from poisonlens.adapters.table_base import Chunk, TableAdapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.schemas import ContainerInfo, Selection

_ALLOWED_FUNCTIONS = {"count"}


def _authorizer(action: int, arg1: str | None, arg2: str | None, _db: str | None, _trigger: str | None) -> int:
    if action in (sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ):
        return sqlite3.SQLITE_OK
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in _ALLOWED_FUNCTIONS:
        return sqlite3.SQLITE_OK
    return sqlite3.SQLITE_DENY


@contextmanager
def open_readonly(path: Path) -> Iterator[sqlite3.Connection]:
    uri = Path(path).resolve().as_uri() + "?mode=ro&immutable=1"
    conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    try:
        if hasattr(conn, "enable_load_extension"):
            conn.enable_load_extension(False)
        conn.set_authorizer(_authorizer)
        yield conn
    finally:
        conn.close()


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


class SqliteAdapter(TableAdapter):
    name = "sqlite"
    specificity = 2

    def can_handle(self, src: Source) -> float:
        return 1.0 if not src.is_dir and src.kind == "sqlite" else 0.0

    def format_name(self, src: Source) -> str:
        return "sqlite"

    def containers(self, src: Source, cfg: ScanConfig) -> list[ContainerInfo]:
        out = []
        with open_readonly(src.path) as conn:
            try:
                rows = conn.execute(
                    "SELECT name, type, sql FROM sqlite_master WHERE type IN ('table', 'view')"
                ).fetchall()
            except sqlite3.DatabaseError as exc:
                raise UnsupportedFormatError(f"unreadable SQLite database: {exc}") from exc
            for name, kind, sql in rows:
                if name.startswith("sqlite_"):
                    continue
                virtual = (sql or "").lstrip().upper().startswith("CREATE VIRTUAL TABLE")
                n = None
                note = ""
                if virtual:
                    note = "virtual table: not loaded"
                else:
                    try:
                        n = int(conn.execute(f"SELECT count(*) FROM {quote_ident(name)}").fetchone()[0])  # noqa: S608
                    except sqlite3.DatabaseError as exc:
                        note = f"not readable: {exc}"
                out.append(
                    ContainerInfo(
                        name=name, kind=kind, n_records=n, selectable=not virtual and n is not None, note=note
                    )
                )
        return out

    def default_selection(self, src: Source, containers: list[ContainerInfo], cfg: ScanConfig) -> Selection:
        tables = [c for c in containers if c.selectable and c.kind == "table"] or [
            c for c in containers if c.selectable
        ]
        if not tables:
            raise UnsupportedFormatError("the database has no readable tables")
        return Selection(container=max(tables, key=lambda c: c.n_records or 0).name)

    def count_records(self, src: Source, selection: Selection, cfg: ScanConfig) -> int | None:
        for c in self.containers(src, cfg):
            if c.name == selection.container:
                return c.n_records
        return None

    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        names = {c.name: c for c in self.containers(src, cfg)}
        table = selection.container
        if table is None or table not in names or not names[table].selectable:
            raise UnsupportedFormatError(f"table {table!r} is not a readable table in this database")
        with open_readonly(src.path) as conn:
            cur = conn.execute(f"SELECT * FROM {quote_ident(table)}")  # noqa: S608 - name validated above
            cols = [d[0] for d in cur.description]
            row = 0
            while True:
                rows = cur.fetchmany(chunk_rows)
                if not rows:
                    break
                yield Chunk(pd.DataFrame.from_records(rows, columns=cols), src.ref(), table, row)
                row += len(rows)
