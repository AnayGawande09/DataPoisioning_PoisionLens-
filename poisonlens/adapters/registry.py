"""Adapter registry: rank adapters by ``can_handle``; ties go to the more specific adapter.

Archive uploads arrive as a directory (``sandbox/``). Directory-shaped datasets (image /
audio / text sets, CIFAR, IDX, HF) are claimed by their adapters; otherwise the
:class:`ArchiveMemberAdapter` exposes each data file in the archive as a selectable
container and delegates to that file's adapter (default: the largest data file).
"""

from __future__ import annotations

from pathlib import Path

from poisonlens.adapters.arrays import ArrayAdapter
from poisonlens.adapters.audio_set import AudioSetAdapter
from poisonlens.adapters.base import DatasetAdapter, LoadResult, Source, member_ext
from poisonlens.adapters.columnar import ColumnarAdapter
from poisonlens.adapters.database import SqliteAdapter
from poisonlens.adapters.image_set import ImageSetAdapter
from poisonlens.adapters.jsonfam import JsonAdapter
from poisonlens.adapters.mlnative import CifarBinaryAdapter, HFDatasetAdapter, IdxAdapter
from poisonlens.adapters.serialized import SerializedAdapter
from poisonlens.adapters.spreadsheet import SpreadsheetAdapter
from poisonlens.adapters.statpkg import StatPackageAdapter
from poisonlens.adapters.table_base import merge_selection
from poisonlens.adapters.tabular import DelimitedAdapter
from poisonlens.adapters.text_set import ConllAdapter, TextDocumentSetAdapter
from poisonlens.adapters.xmlrec import XmlAdapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.schemas import ContainerInfo, DatasetProfile, Selection
from poisonlens.ingest.sniff import sniff

DATA_FILE_EXTS = {
    "csv",
    "tsv",
    "txt",
    "psv",
    "json",
    "jsonl",
    "ndjson",
    "xlsx",
    "xlsm",
    "xls",
    "ods",
    "parquet",
    "feather",
    "arrow",
    "orc",
    "avro",
    "sav",
    "dta",
    "sas7bdat",
    "npy",
    "npz",
    "h5",
    "hdf5",
    "mat",
    "sqlite",
    "db",
    "xml",
    "conll",
    "conllu",
    "pkl",
    "pickle",
    "joblib",
    "pt",
    "pth",
}


def member_source(dir_src: Source, rel: str) -> Source:
    path = dir_src.member_path(rel)
    kind = sniff(path, rel.rsplit("/", 1)[-1]).kind
    return Source(
        path=path,
        kind=kind,
        name=rel.rsplit("/", 1)[-1],
        payload_prefix=dir_src.payload_prefix,
        self_ref=dir_src.ref(rel),
    )


class ArchiveMemberAdapter(DatasetAdapter):
    name = "archive_member"
    specificity = 0

    def _data_files(self, src: Source) -> list[str]:
        return [m for m in src.members() if member_ext(m) in DATA_FILE_EXTS]

    def can_handle(self, src: Source) -> float:
        return 0.5 if src.is_dir and self._data_files(src) else 0.0

    def _containers(self, src: Source) -> list[ContainerInfo]:
        return [
            ContainerInfo(name=m, kind="file", note=f"{src.member_path(m).stat().st_size} bytes")
            for m in self._data_files(src)
        ]

    def _inner(self, src: Source, member: str | None) -> tuple[str, Source, DatasetAdapter]:
        files = self._data_files(src)
        if member is None:
            # Prefer non-serialized files, then the largest.
            ranked = sorted(
                files,
                key=lambda m: (
                    member_ext(m) in {"pkl", "pickle", "joblib", "pt", "pth"},
                    -src.member_path(m).stat().st_size,
                ),
            )
            if not ranked:
                raise UnsupportedFormatError("the archive contains no supported data files")
            member = ranked[0]
        elif member not in files:
            raise UnsupportedFormatError(f"{member!r} is not a data file in this archive")
        inner_src = member_source(src, member)
        return member, inner_src, choose_adapter(inner_src)

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        member, inner_src, adapter = self._inner(src, selection.member if selection else None)
        inner_sel = selection.model_copy(update={"member": None}) if selection else None
        prof = adapter.inspect(inner_src, cfg, inner_sel)
        others = [c for c in self._containers(src) if c.name != member]
        return prof.model_copy(
            update={
                "adapter": f"{self.name}:{adapter.name}",
                "containers": [ContainerInfo(name=member, kind="file", note="selected"), *others, *prof.containers],
                "selection": prof.selection.model_copy(update={"member": member}),
                "warnings": prof.warnings
                + ([f"archive has {len(others) + 1} data files; using {member}"] if others else []),
            }
        )

    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        sel = merge_selection(profile.selection, selection)
        _member, inner_src, adapter = self._inner(src, sel.member)
        return adapter.load(inner_src, profile, sel.model_copy(update={"member": None}), canonical, cfg)


ADAPTERS: list[DatasetAdapter] = [
    SerializedAdapter(),
    DelimitedAdapter(),
    SpreadsheetAdapter(),
    JsonAdapter(),
    ColumnarAdapter(),
    StatPackageAdapter(),
    ArrayAdapter(),
    SqliteAdapter(),
    XmlAdapter(),
    ConllAdapter(),
    ImageSetAdapter(),
    AudioSetAdapter(),
    TextDocumentSetAdapter(),
    CifarBinaryAdapter(),
    IdxAdapter(),
    HFDatasetAdapter(),
    ArchiveMemberAdapter(),
]
BY_NAME = {a.name: a for a in ADAPTERS}


def rank_adapters(src: Source) -> list[tuple[float, DatasetAdapter]]:
    scored = [(a.can_handle(src), a) for a in ADAPTERS]
    return sorted((s for s in scored if s[0] > 0), key=lambda s: (-s[0], -s[1].specificity))


def choose_adapter(src: Source) -> DatasetAdapter:
    ranked = rank_adapters(src)
    if not ranked:
        what = "this archive's contents" if src.is_dir else f"files of type '{src.kind}' (.{src.ext})"
        raise UnsupportedFormatError(f"no adapter can read {what}", detected_kind=src.kind)
    return ranked[0][1]


def adapter_for_profile(profile: DatasetProfile) -> DatasetAdapter:
    name = profile.adapter.split(":", 1)[0]
    if name not in BY_NAME:
        raise UnsupportedFormatError(f"unknown adapter {profile.adapter!r}")
    return BY_NAME[name]
