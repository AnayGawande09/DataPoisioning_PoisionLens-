"""Streaming loads: column types that change after the first chunk keep one stable schema."""

from __future__ import annotations

import pyarrow.parquet as pq

from poisonlens.adapters.base import Source
from poisonlens.adapters.tabular import DelimitedAdapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.schemas import Selection


def test_type_drift_across_chunks(tmp_path):
    lines = ["n,mixed,flag,label"]
    for i in range(45):
        mixed = str(i) if i < 30 else ("3.5" if i < 40 else "oops")  # int -> float -> string
        n = str(i) if i != 37 else ""  # a missing value late in the file keeps the column integer
        lines.append(f"{n},{mixed},{'true' if i % 2 else 'false'},{'a' if i % 3 else 'b'}")
    path = tmp_path / "drift.csv"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    cfg = ScanConfig()
    cfg.inspect.chunk_rows = 10  # force 5 chunks
    src = Source(path=path, kind="text", name="drift.csv")
    adapter = DelimitedAdapter()
    profile = adapter.inspect(src, cfg)
    result = adapter.load(src, profile, Selection(), tmp_path / "canonical", cfg)

    assert result.n_records == 45
    table = pq.read_table(tmp_path / "canonical" / "features_raw.parquet")
    types = {f.name: str(f.type) for f in table.schema}
    assert types == {"record_id": "string", "n": "int64", "mixed": "string", "flag": "bool", "label": "string"}
    df = table.to_pandas()
    assert df["n"].isna().sum() == 1
    assert df["mixed"].tolist()[:2] == ["0", "1"] and df["mixed"].iloc[-1] == "oops"
    assert pq.ParquetFile(tmp_path / "canonical" / "features_raw.parquet").metadata.num_row_groups == 5


def test_string_columns_get_mean_length(tmp_path):
    # pandas 3 reads strings as the new "str" dtype; profiling must still treat them as text.
    path = tmp_path / "s.csv"
    path.write_text("city,label\n" + "".join(f"Pune{i},{'a' if i % 2 else 'b'}\n" for i in range(25)), encoding="utf-8")
    prof = DelimitedAdapter().inspect(Source(path=path, kind="text", name="s.csv"), ScanConfig())
    city = next(c for c in prof.columns if c.name == "city")
    assert city.mean_length is not None and city.mean_length > 4


def test_txt_without_delimiter_is_line_records(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("first note here\n\nsecond note\nthird\n", encoding="utf-8")
    prof = DelimitedAdapter().inspect(Source(path=path, kind="text", name="notes.txt"), ScanConfig())
    assert prof.n_records == 3 and [c.name for c in prof.columns] == ["text"]


def test_utf16_and_semicolon_csv(tmp_path):
    path = tmp_path / "eu.csv"
    rows = ["name;score;label"] + [f"Zoë {i};{i},5;{'x' if i % 2 else 'y'}" for i in range(25)]
    path.write_bytes("\n".join(rows).encode("utf-16"))
    prof = DelimitedAdapter().inspect(Source(path=path, kind="text", name="eu.csv"), ScanConfig())
    assert [c.name for c in prof.columns] == ["name", "score", "label"]
    assert prof.label_chosen == "label" and prof.n_records == 25
