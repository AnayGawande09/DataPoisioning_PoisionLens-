"""Text corpora that are not a single table.

* **Documents**: ``.txt`` files in class folders (``pos/1.txt``, ``train/neg/7.txt``) or with
  a manifest. Each file is one record; ``payload_ref`` points at the file.
* **CoNLL** (``.conll``, ``.conllu``): one record per sentence (blank-line separated), text
  is the space-joined first column. Token tags are not sentence labels, so the profile is
  unlabeled and says why. JSONL corpora with a ``text`` field are handled by the JSON adapter.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pandas as pd

from poisonlens.adapters.base import DatasetAdapter, LoadResult, Source, member_ext, split_from_path
from poisonlens.adapters.fileset import RecordRow, profile_from_rows, write_rows
from poisonlens.adapters.layouts import find_manifest, folder_labels
from poisonlens.adapters.table_base import Chunk, TableAdapter, merge_selection
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import DatasetProfile, Modality, Selection

CONLL_EXTS = {"conll", "conllu"}


class TextDocumentSetAdapter(DatasetAdapter):
    name = "text_documents"
    specificity = 4

    def can_handle(self, src: Source) -> float:
        if not src.is_dir:
            return 0.0
        members = src.members()
        docs = [m for m in members if member_ext(m) == "txt" and "/" in m]
        if not docs:
            return 0.0
        _labels, foldered = folder_labels(docs)
        share = len(docs) / max(1, len(members))
        return 0.85 if foldered and share >= 0.5 else (0.4 if share >= 0.8 else 0.0)

    def _rows(self, src: Source, cfg: ScanConfig) -> tuple[list[RecordRow], str, str]:
        docs = [m for m in src.members() if member_ext(m) == "txt"]
        if not docs:
            raise UnsupportedFormatError("no text documents found")
        manifest = find_manifest(src, docs, cfg)
        if manifest:
            labels, member, col = manifest
            source, reason = f"{member}:{col}", f"manifest {member}, column '{col}'"
        else:
            labels, ok = folder_labels(docs)
            source, reason = ("folder", "class from parent folder name") if ok else ("", "")
            if not ok:
                labels = {}
        rows = [
            RecordRow(source_file=src.ref(d), payload_ref=src.ref(d), label_raw=labels.get(d), split=split_from_path(d))
            for d in docs
        ]
        return rows, source, reason

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        rows, source, reason = self._rows(src, cfg)
        return profile_from_rows(
            rows,
            n_records=len(rows),
            fmt="text_documents",
            adapter=self.name,
            modality=Modality.TEXT,
            label_source=source or None,
            label_reason=reason,
            cfg=cfg,
            selection=merge_selection(Selection(), selection),
        )

    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        rows, _s, _r = self._rows(src, cfg)
        return write_rows(canonical, rows)


class ConllAdapter(TableAdapter):
    name = "conll"
    parse_strings = False
    specificity = 4

    def can_handle(self, src: Source) -> float:
        return 0.95 if not src.is_dir and src.ext in CONLL_EXTS and src.kind == "text" else 0.0

    def format_name(self, src: Source) -> str:
        return "conll"

    def iter_raw(self, src: Source, selection: Selection, chunk_rows: int, cfg: ScanConfig) -> Iterator[Chunk]:
        rows: list[dict[str, str]] = []
        tokens: list[str] = []
        tags: list[str] = []
        start = 0

        def emit() -> None:
            if tokens:
                rows.append({"text": " ".join(tokens), "tags": " ".join(tags)})
            tokens.clear()
            tags.clear()

        with open(os_path(src.path), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.rstrip("\r\n")
                if not line.strip():
                    emit()
                elif not line.startswith("#"):
                    parts = line.split("\t") if "\t" in line else line.split()
                    tokens.append(parts[0] if len(parts) < 10 else parts[1])  # CoNLL-U: FORM is column 2
                    tags.append(parts[-1])
                if len(rows) >= chunk_rows:
                    yield Chunk(pd.DataFrame(rows), src.ref(), None, start)
                    start += len(rows)
                    rows = []
        emit()
        if rows:
            yield Chunk(pd.DataFrame(rows), src.ref(), None, start)

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        base = merge_selection(Selection(text_column="text"), selection)
        prof = super().inspect(src, cfg, base)
        if base.label_column is None:
            reasons = dict(prof.capabilities.reasons)
            reasons["labels"] = (
                "CoNLL files carry token-level tags, not sentence labels. Sentence-level checks "
                "(duplicates, PII, injection) still run."
            )
            caps = prof.capabilities.model_copy(
                update={"labels": False, "probe": False, "detect": False, "reasons": reasons}
            )
            prof = prof.model_copy(
                update={
                    "label_chosen": None,
                    "class_hist": {},
                    "label_candidates": [],
                    "capabilities": caps,
                    "modality": Modality.TEXT,
                    "selection": prof.selection.model_copy(update={"label_column": None}),
                }
            )
        return prof
