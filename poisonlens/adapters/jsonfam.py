"""JSON family: ``.json`` (array of records, an object holding record arrays, or columns)
and ``.jsonl`` / ``.ndjson`` (one record per line, streamed).

Nested objects are flattened to dotted keys up to ``limits.parse.json_max_depth``; deeper
values and lists are kept as JSON strings. More than ``json_max_keys`` distinct keys is a
key-explosion attack and raises :class:`LimitExceededError`.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from typing import Any

import pandas as pd

from poisonlens.adapters.base import Source
from poisonlens.adapters.table_base import Chunk, TableAdapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import LimitExceededError, UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import ContainerInfo, Selection

LINE_EXTS = {"jsonl", "ndjson"}


def flatten(obj: Any, max_depth: int, prefix: str = "", depth: int = 1, out: dict[str, Any] | None = None) -> dict:
    out = {} if out is None else out
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict) and depth < max_depth:
                flatten(v, max_depth, key, depth + 1, out)
            elif isinstance(v, (dict, list)):
                out[key] = json.dumps(v, ensure_ascii=False, sort_keys=True)
            else:
                out[key] = v
    else:
        out[prefix or "value"] = obj if not isinstance(obj, list) else json.dumps(obj, ensure_ascii=False)
    return out


class _KeyGuard:
    def __init__(self, limit: int):
        self.limit = limit
        self.keys: set[str] = set()

    def check(self, rec: dict[str, Any]) -> None:
        self.keys.update(rec)
        if len(self.keys) > self.limit:
            raise LimitExceededError(
                f"JSON records use more than {self.limit} distinct keys",
                limit="json_max_keys",
                limit_value=self.limit,
                observed=len(self.keys),
            )


class JsonAdapter(TableAdapter):
    name = "json"
    specificity = 2

    def can_handle(self, src: Source) -> float:
        if src.is_dir:
            return 0.0
        if src.ext in LINE_EXTS and src.kind in ("json", "text"):
            return 0.95
        if src.ext == "json" and src.kind in ("json", "text"):
            return 0.95
        return 0.4 if src.kind == "json" else 0.0

    def format_name(self, src: Source) -> str:
        return src.ext if src.ext in LINE_EXTS | {"json"} else "json"

    def _is_lines(self, src: Source) -> bool:
        if src.ext in LINE_EXTS:
            return True
        with open(os_path(src.path), "rb") as fh:
            head = fh.read(4096).lstrip()
        return head.startswith(b"{") and b"\n{" in head and src.ext != "json"

    def _load_document(self, src: Source, cfg: ScanConfig) -> Any:
        size = os.path.getsize(os_path(src.path))
        budget = cfg.limits.parse.ram_budget_bytes // 4  # json.load needs several times the file size
        if size > budget:
            raise LimitExceededError(
                f"{src.name} is {size} bytes; whole-document JSON above {budget} bytes must be converted to JSONL",
                limit="ram_budget_bytes",
                limit_value=budget,
                observed=size,
            )
        with open(os_path(src.path), encoding="utf-8-sig") as fh:
            try:
                return json.load(fh)
            except json.JSONDecodeError as exc:
                raise UnsupportedFormatError(f"invalid JSON: {exc}") from exc

    def containers(self, src: Source, cfg: ScanConfig) -> list[ContainerInfo]:
        if self._is_lines(src):
            return []
        doc = self._load_document(src, cfg)
        if isinstance(doc, dict):
            return [
                ContainerInfo(name=k, kind="key", n_records=len(v))
                for k, v in doc.items()
                if isinstance(v, list) and v and all(isinstance(x, dict) for x in v[:100])
            ]
        return []

    def default_selection(self, src: Source, containers: list[ContainerInfo], cfg: ScanConfig) -> Selection:
        if containers:
            best = max(containers, key=lambda c: c.n_records or 0)
            return Selection(container=best.name)
        return Selection()

    def _records(self, src: Source, selection: Selection, cfg: ScanConfig) -> Iterator[dict[str, Any]]:
        depth = cfg.limits.parse.json_max_depth
        if self._is_lines(src):
            with open(os_path(src.path), encoding="utf-8-sig", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # malformed line skipped (counted by the caller)
                    yield flatten(obj, depth)
            return
        doc = self._load_document(src, cfg)
        if isinstance(doc, list):
            records = doc
        elif isinstance(doc, dict) and selection.container is not None:
            if selection.container not in doc:
                raise UnsupportedFormatError(f"key {selection.container!r} not found")
            records = doc[selection.container]
        elif isinstance(doc, dict) and doc and all(isinstance(v, list) for v in doc.values()):
            lengths = {len(v) for v in doc.values()}
            if len(lengths) != 1:
                raise UnsupportedFormatError("column-oriented JSON with unequal column lengths")
            keys = list(doc)
            records = [dict(zip(keys, vals, strict=True)) for vals in zip(*doc.values(), strict=True)]
        else:
            records = [doc]
        for rec in records:
            yield flatten(rec, depth)

    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        guard = _KeyGuard(cfg.limits.parse.json_max_keys)
        buf: list[dict[str, Any]] = []
        row = 0
        for rec in self._records(src, selection, cfg):
            guard.check(rec)
            buf.append(rec)
            if len(buf) >= chunk_rows:
                yield Chunk(pd.DataFrame.from_records(buf), src.ref(), selection.container, row)
                row += len(buf)
                buf = []
        if buf:
            yield Chunk(pd.DataFrame.from_records(buf), src.ref(), selection.container, row)
