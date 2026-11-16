"""Audio datasets: archive/folder of wav / flac / ogg / mp3 with folder labels or a manifest.

Files are checked with ``soundfile.info`` (libsndfile; mp3 needs libsndfile >= 1.1). No
ffmpeg is invoked. Unreadable files are skipped and reported.
"""

from __future__ import annotations

from pathlib import Path

from poisonlens.adapters.base import DatasetAdapter, LoadResult, Source, member_ext, split_from_path
from poisonlens.adapters.fileset import RecordRow, profile_from_rows, write_rows
from poisonlens.adapters.layouts import find_manifest, folder_labels
from poisonlens.adapters.table_base import merge_selection
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsupportedFormatError
from poisonlens.core.paths import os_path
from poisonlens.core.schemas import DatasetProfile, Modality, Selection

AUDIO_EXTS = {"wav", "flac", "ogg", "mp3"}


def check_audio(path: Path) -> str | None:
    try:
        import soundfile as sf
    except ImportError:
        return "audio support needs the optional 'soundfile' package"
    try:
        info = sf.info(os_path(path))
    except Exception as exc:  # noqa: BLE001 - any libsndfile failure means unreadable
        return f"{type(exc).__name__}: {exc}"
    if info.frames <= 0 or info.samplerate <= 0:
        return "empty or invalid audio stream"
    return None


class AudioSetAdapter(DatasetAdapter):
    name = "audio_set"
    specificity = 5

    def can_handle(self, src: Source) -> float:
        if not src.is_dir:
            return 0.0
        members = src.members()
        audio = [m for m in members if member_ext(m) in AUDIO_EXTS]
        return 0.9 if audio and len(audio) >= 0.5 * len(members) else (0.3 if audio else 0.0)

    def _rows(self, src: Source, cfg: ScanConfig, limit: int | None) -> tuple[list[RecordRow], str, str, list[str]]:
        files = [m for m in src.members() if member_ext(m) in AUDIO_EXTS]
        if not files:
            raise UnsupportedFormatError("no audio files found")
        manifest = find_manifest(src, files, cfg)
        if manifest:
            labels, member, col = manifest
            label_source, reason = f"{member}:{col}", f"manifest {member}, column '{col}'"
        else:
            labels, ok = folder_labels(files)
            label_source, reason = ("folder", "class from parent folder name") if ok else ("", "")
            if not ok:
                labels = {}
        rows: list[RecordRow] = []
        warn: list[str] = []
        bad = 0
        for i, rel in enumerate(files):
            if limit is None or i < limit:
                err = check_audio(src.member_path(rel))
                if err:
                    bad += 1
                    if len(warn) < 50:
                        warn.append(f"skipped {rel}: {err}")
                    continue
            rows.append(
                RecordRow(
                    source_file=src.ref(rel),
                    payload_ref=src.ref(rel),
                    label_raw=labels.get(rel),
                    split=split_from_path(rel),
                )
            )
        if bad:
            warn.insert(0, f"{bad} unreadable audio file(s) skipped")
        return rows, label_source, reason, warn

    def inspect(self, src: Source, cfg: ScanConfig, selection: Selection | None = None) -> DatasetProfile:
        rows, label_source, reason, warn = self._rows(src, cfg, cfg.inspect.image_verify_sample)
        return profile_from_rows(
            rows,
            n_records=len(rows),
            fmt="audio_set",
            adapter=self.name,
            modality=Modality.AUDIO,
            label_source=label_source or None,
            label_reason=reason,
            cfg=cfg,
            selection=merge_selection(Selection(), selection),
            warnings=warn,
            sampled=len(rows) > cfg.inspect.image_verify_sample,
        )

    def load(
        self, src: Source, profile: DatasetProfile, selection: Selection, canonical: Path, cfg: ScanConfig
    ) -> LoadResult:
        rows, _s, _r, warn = self._rows(src, cfg, None)
        result = write_rows(canonical, rows)
        result.warnings = warn
        return result
