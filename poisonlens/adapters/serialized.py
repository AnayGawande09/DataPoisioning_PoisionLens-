"""Scan-only adapter for serialized Python objects: pickle, joblib, PyTorch ``.pt/.pth``.

These files can execute code when loaded, so they are **never loaded**. The profile reports
the dataset as unusable for training and asks the user to convert it; the security stage
(F07, Phase 4) scans the pickle opcodes statically.
"""

from __future__ import annotations

import os
from pathlib import Path

from poisonlens.adapters.base import DatasetAdapter, LoadResult, Source
from poisonlens.adapters.profile import capabilities
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import DatasetProfile, Modality, Selection

KINDS = {"pickle", "zlib", "pytorch_zip"}
EXTS = {"pkl", "pickle", "joblib", "pt", "pth"}
REASON = (
    "Serialized Python objects can run code when loaded, so PoisonLens only scans them statically. "
    "Convert the data to CSV, Parquet, NumPy (.npy without objects) or safetensors to analyze it."
)


class SerializedAdapter(DatasetAdapter):
    name = "serialized"
    specificity = 10

    def can_handle(self, src: Source) -> float:
        if src.is_dir:
            return 0.0
        if src.kind in KINDS:
            return 1.0
        return 0.9 if src.ext in EXTS else 0.0

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        size = os.path.getsize(os_path(src.path))
        return DatasetProfile(
            format=src.ext if src.ext in EXTS else src.kind,
            modality=Modality.MIXED,
            n_records=0,
            capabilities=capabilities(
                modality=Modality.MIXED, n_records=0, label=None, n_classes=0, cfg=cfg, scan_only_reason=REASON
            ),
            adapter=self.name,
            warnings=[f"Scan-only: {size} bytes of serialized data were not loaded."],
        )

    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        raise UnsupportedFormatError(REASON)
