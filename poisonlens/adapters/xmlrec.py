"""XML record files, parsed only with ``defusedxml`` (no entities, no external references).

The record element is a direct child of the root; by default the most frequent child tag.
Each record becomes ``{child_tag: text, "@attr": value, ...}`` (one level of nesting is
flattened as ``parent.child``). Parsing is streaming (``iterparse`` + ``clear``).
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterator
from typing import Any

import pandas as pd
from defusedxml import DefusedXmlException
from defusedxml.ElementTree import iterparse

from poisonlens.adapters.base import Source
from poisonlens.adapters.table_base import Chunk, TableAdapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsafeFileError, UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import ContainerInfo, Selection


def _local(tag: Any) -> str:
    text = str(tag)
    return text.rsplit("}", 1)[-1] if "}" in text else text


def _events(src: Source) -> Iterator[tuple[str, Any]]:
    try:
        yield from iterparse(os_path(src.path), events=("start", "end"), forbid_dtd=False)
    except DefusedXmlException as exc:
        raise UnsafeFileError(f"XML uses forbidden constructs ({type(exc).__name__})", check_id="F09") from exc
    except Exception as exc:  # ParseError and friends
        raise UnsupportedFormatError(f"invalid XML: {exc}") from exc


def _record(elem: Any) -> dict[str, Any]:
    rec: dict[str, Any] = {f"@{_local(k)}": v for k, v in elem.attrib.items()}
    for child in elem:
        key = _local(child.tag)
        grandchildren = list(child)
        if grandchildren:
            for g in grandchildren:
                rec[f"{key}.{_local(g.tag)}"] = (g.text or "").strip() or None
        else:
            rec[key] = (child.text or "").strip() or None
        for ak, av in child.attrib.items():
            rec[f"{key}@{_local(ak)}"] = av
    if not len(elem) and (elem.text or "").strip():
        rec["text"] = elem.text.strip()
    return rec


class XmlAdapter(TableAdapter):
    name = "xml"
    parse_strings = True
    specificity = 2

    def can_handle(self, src: Source) -> float:
        if src.is_dir:
            return 0.0
        if src.kind == "xml" and src.ext == "xml":
            return 0.95
        return 0.5 if src.kind == "xml" else 0.0

    def format_name(self, src: Source) -> str:
        return "xml"

    def containers(self, src: Source, cfg: ScanConfig) -> list[ContainerInfo]:
        depth = 0
        counts: Counter[str] = Counter()
        root = None
        for event, elem in _events(src):
            if event == "start":
                depth += 1
                if depth == 1:
                    root = elem
                elif depth == 2:
                    counts[_local(elem.tag)] += 1
            else:
                depth -= 1
                if depth == 1 and root is not None:
                    root.clear()
        return [ContainerInfo(name=tag, kind="element", n_records=n) for tag, n in counts.most_common()]

    def default_selection(self, src: Source, containers: list[ContainerInfo], cfg: ScanConfig) -> Selection:
        if not containers:
            raise UnsupportedFormatError("XML root has no child elements to use as records")
        return Selection(container=containers[0].name)

    def count_records(self, src: Source, selection: Selection, cfg: ScanConfig) -> int | None:
        for c in self.containers(src, cfg):
            if c.name == selection.container:
                return c.n_records
        return 0

    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        want = selection.container
        depth = 0
        root = None
        buf: list[dict[str, Any]] = []
        row = 0
        for event, elem in _events(src):
            if event == "start":
                depth += 1
                if depth == 1:
                    root = elem
                continue
            depth -= 1
            if depth == 1:
                if _local(elem.tag) == want:
                    buf.append(_record(elem))
                if root is not None:
                    root.clear()
                if len(buf) >= chunk_rows:
                    yield Chunk(pd.DataFrame.from_records(buf), src.ref(), want, row)
                    row += len(buf)
                    buf = []
        if buf:
            yield Chunk(pd.DataFrame.from_records(buf), src.ref(), want, row)
