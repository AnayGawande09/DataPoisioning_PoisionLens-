"""Shared inspect/load for every adapter whose records are rows of a table.

A subclass only says how to list containers (sheets, tables, keys...) and how to stream
raw chunks; profiling, label handling, the two-pass schema inference and the CDR writing
live here once.
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

import pandas as pd

from poisonlens.adapters.base import (
    SPLIT_VOCAB,
    DatasetAdapter,
    FeatureWriter,
    LoadResult,
    ManifestWriter,
    Source,
    infer_kinds,
    normalize_columns,
    record_id,
    sha256_file,
)
from poisonlens.adapters.profile import (
    capabilities,
    column_profiles,
    detect_split_column,
    label_candidates,
    normalize_label,
    text_column_candidates,
)
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.schemas import ContainerInfo, DatasetProfile, Modality, Selection, SplitInfo


@dataclass
class Chunk:
    df: pd.DataFrame
    source_file: str
    sheet: str | None = None
    row_start: int = 0


def merge_selection(default: Selection, override: Selection | None) -> Selection:
    if override is None:
        return default
    data = default.model_dump()
    data.update({k: v for k, v in override.model_dump().items() if v is not None})
    return Selection.model_validate(data)


def _norm_split(v: object) -> str | None:
    if v is None or (isinstance(v, float) and pd.isna(v)):
        return None
    text = str(v).strip().lower()
    return SPLIT_VOCAB.get(text, text or None)


class TableAdapter(DatasetAdapter):
    #: parse numbers/booleans out of string cells (CSV, XML); typed sources keep their types
    parse_strings: ClassVar[bool] = False

    def format_name(self, src: Source) -> str:
        return src.ext

    def containers(self, src: Source, cfg: ScanConfig) -> list[ContainerInfo]:
        return []

    def default_selection(self, src: Source, containers: list[ContainerInfo], cfg: ScanConfig) -> Selection:
        return Selection()

    @abstractmethod
    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        """Yield raw chunks for the selected container(s)."""

    def count_records(self, src: Source, selection: Selection, cfg: ScanConfig) -> int | None:
        """Fast exact count from metadata when the format has one; None = count by streaming."""
        return None

    def iter_chunks(self, src: Source, selection: Selection, chunk_rows: int) -> Iterator[pd.DataFrame]:
        cfg = ScanConfig()
        for c in self.iter_raw(src, selection, chunk_rows, cfg):
            yield normalize_columns(c.df)

    # ------------------------------------------------------------------ inspect

    def _sample(self, src: Source, sel: Selection, cfg: ScanConfig) -> pd.DataFrame:
        want = cfg.limits.parse.inspect_sample_rows
        parts: list[pd.DataFrame] = []
        got = 0
        for c in self.iter_raw(src, sel, min(want, cfg.inspect.chunk_rows), cfg):
            df = normalize_columns(c.df)
            parts.append(df.head(want - got))
            got += len(parts[-1])
            if got >= want:
                break
        if not parts:
            return pd.DataFrame()
        return pd.concat(parts, ignore_index=True, sort=False)

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        containers = self.containers(src, cfg)
        sel = merge_selection(self.default_selection(src, containers, cfg), selection)
        sample = self._sample(src, sel, cfg)
        n = self.count_records(src, sel, cfg)
        sampled = True
        if n is None:
            n = sum(len(c.df) for c in self.iter_raw(src, sel, cfg.inspect.chunk_rows, cfg))
        if n <= len(sample):
            sampled = False
        split_col = detect_split_column(sample) if len(sample) else None
        exclude = {split_col} if split_col else set()
        cands = label_candidates(sample, cfg, exclude)
        label: str | None
        if sel.label_column is not None:
            if sel.label_column not in sample.columns:
                raise UnsupportedFormatError(f"label column {sel.label_column!r} not found")
            label = sel.label_column
        else:
            top = cands[0] if cands else None
            label = top.column if top and top.score >= cfg.inspect.label_suggest_min_score else None
        text_excl = exclude | ({label} if label else set())
        text_col = sel.text_column
        if text_col is None:
            text_cands = text_column_candidates(sample, cfg, text_excl)
            others = [c for c in sample.columns if c not in text_excl]
            if text_cands and len(others) <= 3:
                text_col = text_cands[0]
        modality = Modality.TEXT if text_col else Modality.TABULAR
        hist: dict[str, int] = {}
        regression = False
        if label is not None:
            values = sample[label].map(normalize_label).dropna()
            hist = {str(k): int(v) for k, v in values.value_counts().sort_index().items()}
            cand = next((c for c in cands if c.column == label), None)
            regression = bool(cand and "regression" in cand.reason)
        splits = None
        if split_col:
            counts = sample[split_col].map(_norm_split).dropna().value_counts()
            splits = SplitInfo(column=split_col, counts={str(k): int(v) for k, v in counts.items()})
        sel = sel.model_copy(update={"label_column": label, "text_column": text_col})
        return DatasetProfile(
            format=self.format_name(src),
            modality=modality,
            n_records=int(n),
            columns=column_profiles(sample),
            label_candidates=cands,
            label_chosen=label,
            splits=splits,
            class_hist=hist,
            capabilities=capabilities(
                modality=modality, n_records=int(n), label=label, n_classes=len(hist), cfg=cfg, regression=regression
            ),
            adapter=self.name,
            containers=containers,
            selection=sel,
            text_column=text_col,
            sampled=sampled,
        )

    # ------------------------------------------------------------------ load

    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        sel = merge_selection(profile.selection, selection)
        label = sel.label_column
        split_col = profile.splits.column if profile.splits else None
        chunk_rows = cfg.inspect.chunk_rows
        kinds, _ = infer_kinds(
            (normalize_columns(c.df) for c in self.iter_raw(src, sel, chunk_rows, cfg)),
            parse_strings=self.parse_strings,
        )
        if label is not None and label not in kinds:
            raise UnsupportedFormatError(f"label column {label!r} not found in the selected data")
        fw = FeatureWriter(canonical, kinds)
        mw = ManifestWriter(canonical)
        i = 0
        for c in self.iter_raw(src, sel, chunk_rows, cfg):
            df = normalize_columns(c.df)
            m = len(df)
            if m == 0:
                continue
            ids = [record_id(i + k) for k in range(m)]
            fw.write(ids, df)
            mw.append(
                {
                    "record_id": ids,
                    "source_file": [c.source_file] * m,
                    "sheet": [c.sheet] * m,
                    "row": list(range(c.row_start, c.row_start + m)),
                    "split": df[split_col].map(_norm_split).tolist() if split_col in df.columns else None,
                    "label_raw": df[label].map(normalize_label).tolist() if label in df.columns else None,
                }
            )
            i += m
        features = fw.close()
        manifest, label_names = mw.finish()
        return LoadResult(
            n_records=mw.n,
            label_names=label_names,
            class_hist={k: mw.labels[k] for k in label_names},
            split_counts=dict(mw.splits),
            artifacts={"manifest.parquet": sha256_file(manifest), "features_raw.parquet": sha256_file(features)},
        )
