"""Delimited text: CSV / TSV / PSV / delimited TXT (compressed singles arrive already
decompressed in the sandbox). Encoding via charset-normalizer, delimiter via ``csv.Sniffer``,
streamed with pandas ``chunksize``. A ``.txt`` with no delimiter becomes one text record per line.
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from dataclasses import dataclass

import pandas as pd
from charset_normalizer import from_bytes

from poisonlens.adapters.base import Source
from poisonlens.adapters.table_base import Chunk, TableAdapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import Selection

DELIMITED_EXTS = {"csv", "tsv", "txt", "psv"}
_SAMPLE = 256 * 1024


@dataclass
class Dialect:
    encoding: str
    delimiter: str | None  # None => line mode


def sniff_dialect(src: Source) -> Dialect:
    with open(os_path(src.path), "rb") as fh:
        raw = fh.read(_SAMPLE)
    if raw.startswith(b"\xef\xbb\xbf"):
        encoding = "utf-8-sig"
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        encoding = "utf-16"
    else:
        best = from_bytes(raw).best() if raw else None
        encoding = best.encoding if best is not None else "utf-8"
        if encoding in ("ascii", "utf_8"):
            encoding = "utf-8"
    text = raw.decode(encoding, errors="replace")
    lines = text.splitlines()[:50]
    if len(raw) == _SAMPLE and lines:
        lines = lines[:-1]  # last line may be cut mid-way
    sample = "\n".join(lines)
    forced = {"tsv": "\t", "psv": "|"}.get(src.ext)
    if forced:
        return Dialect(encoding, forced)
    try:
        delim: str | None = csv.Sniffer().sniff(sample, delimiters=",\t;|").delimiter
    except csv.Error:
        delim = None
    if delim is None:
        delim = None if src.ext == "txt" else ","
    return Dialect(encoding, delim)


class DelimitedAdapter(TableAdapter):
    name = "delimited"
    parse_strings = True
    specificity = 1

    def can_handle(self, src: Source) -> float:
        if src.is_dir:
            return 0.0
        if src.kind == "text" and src.ext in DELIMITED_EXTS:
            return 0.9
        if src.kind == "text" and src.ext == "conll":
            return 0.0
        return 0.2 if src.kind == "text" and src.ext not in {"json", "jsonl", "ndjson", "xml"} else 0.0

    def format_name(self, src: Source) -> str:
        return src.ext if src.ext in DELIMITED_EXTS else "csv"

    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        d = sniff_dialect(src)
        if d.delimiter is None:
            yield from self._lines(src, d.encoding, chunk_rows)
            return
        reader = pd.read_csv(
            os_path(src.path),
            sep=d.delimiter,
            encoding=d.encoding,
            encoding_errors="replace",
            dtype=str,
            keep_default_na=True,
            chunksize=chunk_rows,
            on_bad_lines="skip",
            engine="c",
            skip_blank_lines=True,
        )
        row = 0
        with reader:
            for df in reader:
                yield Chunk(df, src.ref(), None, row)
                row += len(df)

    def _lines(self, src: Source, encoding: str, chunk_rows: int) -> Iterator[Chunk]:
        buf: list[str] = []
        row = 0
        with open(os_path(src.path), encoding=encoding, errors="replace") as fh:
            for line in fh:
                text = line.rstrip("\r\n")
                if not text.strip():
                    continue
                buf.append(text)
                if len(buf) >= chunk_rows:
                    yield Chunk(pd.DataFrame({"text": buf}), src.ref(), None, row)
                    row += len(buf)
                    buf = []
        if buf:
            yield Chunk(pd.DataFrame({"text": buf}), src.ref(), None, row)
