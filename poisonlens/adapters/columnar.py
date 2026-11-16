"""Columnar formats: Parquet (row-group batches), Feather/Arrow IPC, ORC (stripes), Avro (fastavro)."""

from __future__ import annotations

from collections.abc import Iterator

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from poisonlens.adapters.base import Source
from poisonlens.adapters.jsonfam import flatten
from poisonlens.adapters.table_base import Chunk, TableAdapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import Selection

KINDS = {"parquet", "arrow", "orc", "avro"}


class ColumnarAdapter(TableAdapter):
    name = "columnar"
    specificity = 2

    def can_handle(self, src: Source) -> float:
        return 1.0 if not src.is_dir and src.kind in KINDS else 0.0

    def format_name(self, src: Source) -> str:
        return {"arrow": "feather" if src.ext == "feather" else "arrow"}.get(src.kind, src.kind)

    def count_records(self, src: Source, selection: Selection, cfg: ScanConfig) -> int | None:
        path = os_path(src.path)
        if src.kind == "parquet":
            return int(pq.ParquetFile(path).metadata.num_rows)
        if src.kind == "arrow":
            with pa.memory_map(path) as mm:
                reader = pa.ipc.open_file(mm)
                return sum(reader.get_batch(i).num_rows for i in range(reader.num_record_batches))
        if src.kind == "orc":
            from pyarrow import orc

            return int(orc.ORCFile(path).nrows)
        return None

    def _batches(self, src: Source, chunk_rows: int) -> Iterator[pd.DataFrame]:
        path = os_path(src.path)
        if src.kind == "parquet":
            pf = pq.ParquetFile(path)
            try:
                for batch in pf.iter_batches(batch_size=chunk_rows):
                    yield batch.to_pandas()
            finally:
                pf.close()
        elif src.kind == "arrow":
            with pa.memory_map(path) as mm:
                reader = pa.ipc.open_file(mm)
                for i in range(reader.num_record_batches):
                    batch = reader.get_batch(i)
                    for off in range(0, batch.num_rows, chunk_rows):
                        yield batch.slice(off, chunk_rows).to_pandas()
        elif src.kind == "orc":
            try:
                from pyarrow import orc
            except ImportError as exc:  # not built on every platform
                raise UnsupportedFormatError("ORC support is not available in this pyarrow build") from exc
            f = orc.ORCFile(path)
            for i in range(f.nstripes):
                stripe = f.read_stripe(i)
                for off in range(0, stripe.num_rows, chunk_rows):
                    yield stripe.slice(off, chunk_rows).to_pandas()
        elif src.kind == "avro":
            import fastavro

            depth = 6
            with open(path, "rb") as fh:
                buf = []
                for rec in fastavro.reader(fh):
                    buf.append(flatten(rec, depth))
                    if len(buf) >= chunk_rows:
                        yield pd.DataFrame.from_records(buf)
                        buf = []
                if buf:
                    yield pd.DataFrame.from_records(buf)
        else:
            raise UnsupportedFormatError(f"not a columnar format: {src.kind}")

    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        row = 0
        for df in self._batches(src, chunk_rows):
            yield Chunk(df, src.ref(), None, row)
            row += len(df)
