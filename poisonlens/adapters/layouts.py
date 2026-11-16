"""Label layouts shared by image / audio / text-document sets."""

from __future__ import annotations

from collections.abc import Iterable

import pandas as pd

from poisonlens.adapters.base import SPLIT_VOCAB, Source, member_ext
from poisonlens.adapters.profile import label_candidates, normalize_label
from poisonlens.core.config import ScanConfig
from poisonlens.core.paths import os_path

MANIFEST_EXTS = {"csv", "tsv"}
MAX_MANIFEST_BYTES = 64 * 1024 * 1024


def folder_label(rel: str) -> str | None:
    """Class from the nearest parent folder that is not a split name or a container folder."""
    parts = rel.split("/")[:-1]
    skip = set(SPLIT_VOCAB) | {"images", "imgs", "data", "audio", "wavs", "texts", "docs", "documents"}
    for part in reversed(parts):
        if part.lower() not in skip:
            return part
    return None


def folder_labels(members: Iterable[str]) -> tuple[dict[str, str | None], bool]:
    """Folder labels for all members, and whether the layout is really folder-per-class."""
    labels = {m: folder_label(m) for m in members}
    distinct = {v for v in labels.values() if v is not None}
    return labels, len(distinct) >= 2


def find_manifest(src: Source, targets: list[str], cfg: ScanConfig) -> tuple[dict[str, str | None], str, str] | None:
    """Look for a CSV/TSV that maps file names to labels. Returns (labels, manifest member, label column)."""
    by_rel = {t.lower(): t for t in targets}
    by_base: dict[str, str] = {}
    for t in targets:
        by_base.setdefault(t.rsplit("/", 1)[-1].lower(), t)
    for member in src.members():
        if member_ext(member) not in MANIFEST_EXTS:
            continue
        path = src.member_path(member)
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            continue
        try:
            df = pd.read_csv(os_path(path), sep=None, engine="python", dtype=str)
        except Exception:  # noqa: BLE001, S112 - not a usable manifest; try the next candidate
            continue
        if df.empty:
            continue
        base_dir = member.rsplit("/", 1)[0] + "/" if "/" in member else ""
        for col in df.columns:
            values = df[col].dropna().astype(str).str.strip().str.replace("\\", "/", regex=False)
            hits = []
            for v in values:
                key = v.lower()
                hit = by_rel.get(key) or by_rel.get((base_dir + v).lower()) or by_base.get(key.rsplit("/", 1)[-1])
                hits.append(hit)
            if sum(h is not None for h in hits) < max(1, 0.5 * len(values)):
                continue
            cands = label_candidates(df.drop(columns=[col]), cfg, set())
            if not cands:
                continue
            label_col = cands[0].column
            out: dict[str, str | None] = {}
            for hit, lab in zip(hits, df.loc[values.index, label_col], strict=True):
                if hit is not None:
                    out[hit] = normalize_label(lab)
            return out, member, label_col
    return None
