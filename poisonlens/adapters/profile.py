"""Dataset profiling: column stats, label-candidate ranking, split / text detection, capabilities.

Label ranking (score in 0..1, weights are provisional, see docs/CONFIG.md for the threshold):

* 0.55 name — exact ``label, labels, class, target, y, category, sentiment, tag, ...`` = 1.0;
  containing ``label / class / target / category`` = 0.7.
* 0.20 cardinality — 2..max(2, min(max_label_cardinality, N/5)) distinct values.
* 0.10 dtype — integer / string / bool; low-cardinality float 0.7; continuous numeric 0.3 (regression).
* 0.15 position — last column (a common convention).

ID-like columns (almost all values distinct) and the split column are never candidates.
A column is pre-selected only when its score reaches ``inspect.label_suggest_min_score``;
the user always confirms in the UI.
"""

from __future__ import annotations

import pandas as pd

from poisonlens.adapters.base import SPLIT_VOCAB
from poisonlens.core.config import ScanConfig
from poisonlens.core.schemas import Capabilities, ColumnProfile, LabelCandidate, Modality

EXACT_LABEL_NAMES = {
    "label",
    "labels",
    "class",
    "classes",
    "target",
    "y",
    "category",
    "sentiment",
    "tag",
    "class_name",
    "classname",
    "class_label",
    "outcome",
    "polarity",
    "fine_label",
    "coarse_label",
}
PARTIAL_LABEL_TOKENS = ("label", "class", "target", "category")
SPLIT_COLUMN_NAMES = {"split", "subset", "set", "partition", "fold", "dataset", "data_split"}


def column_profiles(sample: pd.DataFrame) -> list[ColumnProfile]:
    out = []
    n = max(1, len(sample))
    for col in sample.columns:
        s = sample[col]
        mean_len = None
        if s.dtype == object or pd.api.types.is_string_dtype(s.dtype):
            lens = s.dropna().astype(str).str.len()
            mean_len = float(lens.mean()) if len(lens) else 0.0
        out.append(
            ColumnProfile(
                name=str(col),
                dtype=str(s.dtype),
                null_rate=float(s.isna().sum()) / n,
                cardinality=int(s.nunique(dropna=True)),
                mean_length=mean_len,
            )
        )
    return out


def normalize_label(value: object) -> str | None:
    """Canonical string form of a raw label (``3.0`` -> ``"3"``, whitespace trimmed)."""
    if value is None:
        return None
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    text = str(value).strip()
    return text or None


def detect_split_column(sample: pd.DataFrame) -> str | None:
    for col in sample.columns:
        values = {str(v).strip().lower() for v in sample[col].dropna().unique()[:50]}
        if not values or len(values) > 6:
            continue
        if values <= set(SPLIT_VOCAB) and (str(col).lower() in SPLIT_COLUMN_NAMES or len(values) >= 2):
            return str(col)
    return None


def _is_numeric(s: pd.Series) -> bool:
    if pd.api.types.is_numeric_dtype(s.dtype) and not pd.api.types.is_bool_dtype(s.dtype):
        return True
    nonnull = s.dropna()
    return bool(len(nonnull)) and pd.to_numeric(nonnull.astype(str), errors="coerce").notna().all()


def label_candidates(sample: pd.DataFrame, cfg: ScanConfig, exclude: set[str]) -> list[LabelCandidate]:
    n = len(sample)
    if n == 0:
        return []
    cols = list(sample.columns)
    out = []
    for pos, col in enumerate(cols):
        name = str(col)
        if name in exclude:
            continue
        s = sample[col].dropna()
        card = int(s.nunique())
        if card < 2:
            continue
        lname = name.strip().lower()
        if lname in EXACT_LABEL_NAMES:
            name_score, why = 1.0, "label-like name"
        elif any(tok in lname for tok in PARTIAL_LABEL_TOKENS):
            name_score, why = 0.7, "name contains a label word"
        else:
            name_score, why = 0.0, ""
        id_like = n >= 20 and card >= 0.95 * len(s)
        if id_like and name_score < 1.0:
            continue
        upper = max(2, min(cfg.inspect.max_label_cardinality, n // 5 if n >= 10 else n))
        card_score = 1.0 if 2 <= card <= upper else 0.0
        numeric = _is_numeric(s)
        values = pd.to_numeric(s.astype(str), errors="coerce") if numeric else None
        integral = values is not None and bool((values % 1 == 0).all())
        if not numeric or integral or pd.api.types.is_bool_dtype(s.dtype):
            dtype_score = 1.0
        elif card <= 20:
            dtype_score = 0.7
        else:
            dtype_score = 0.3
        regression = numeric and card >= cfg.inspect.regression_min_unique and not integral
        last_score = 1.0 if pos == len(cols) - 1 else 0.0
        score = round(0.55 * name_score + 0.20 * card_score + 0.10 * dtype_score + 0.15 * last_score, 4)
        if score <= 0.15:
            continue
        reasons = [r for r in (why, f"{card} distinct values", "last column" if last_score else "") if r]
        if regression:
            reasons.append("continuous numeric: regression target (experimental)")
        out.append(LabelCandidate(column=name, score=min(1.0, score), reason="; ".join(reasons)))
    return sorted(out, key=lambda c: (-c.score, c.column))


TEXT_COLUMN_NAMES = {"text", "sentence", "sentences", "review", "content", "document", "body", "comment", "prompt"}


def text_column_candidates(sample: pd.DataFrame, cfg: ScanConfig, exclude: set[str]) -> list[str]:
    """String columns that hold free text: long on average, or text-named and at least a quarter as long."""
    found = []
    for col in sample.columns:
        if str(col) in exclude:
            continue
        s = sample[col].dropna()
        if s.empty or _is_numeric(s):
            continue
        mean_len = s.astype(str).str.len().mean()
        named = str(col).strip().lower() in TEXT_COLUMN_NAMES
        threshold = cfg.inspect.text_min_mean_length / 4 if named else cfg.inspect.text_min_mean_length
        if mean_len >= threshold:
            found.append((mean_len + (1e6 if named else 0), str(col)))
    return [c for _, c in sorted(found, reverse=True)]


def capabilities(
    *,
    modality: Modality,
    n_records: int,
    label: str | None,
    n_classes: int,
    cfg: ScanConfig,
    scan_only_reason: str | None = None,
    regression: bool = False,
) -> Capabilities:
    reasons: dict[str, str] = {}
    if scan_only_reason:
        for k in ("labels", "quality", "probe", "detect"):
            reasons[k] = scan_only_reason
        return Capabilities(labels=False, security=True, quality=False, probe=False, detect=False, reasons=reasons)
    labels = label is not None and n_classes >= 2
    if label is None:
        reasons["labels"] = (
            "No label column was detected. Pick one if the data is labeled; otherwise only "
            "security, duplicate, outlier and PII checks run."
        )
    elif n_classes < 2:
        reasons["labels"] = f"Label '{label}' has fewer than 2 classes."
    probe = labels
    if probe and n_records < cfg.inspect.min_records_for_probe:
        probe = False
        reasons["probe"] = f"Only {n_records} records; the probe needs at least {cfg.inspect.min_records_for_probe}."
    elif probe and modality is Modality.MIXED:
        probe = False
        reasons["probe"] = "Mixed-modality data is not probed as one dataset yet."
    elif probe and n_classes > cfg.inspect.max_label_cardinality and not regression:
        probe = False
        reasons["probe"] = f"{n_classes} classes exceeds the supported maximum of {cfg.inspect.max_label_cardinality}."
    elif not labels:
        reasons["probe"] = "Training-dynamics detectors need labels."
    if regression and probe:
        reasons["probe"] = "Regression target: probed on a binned target (experimental)."
    detect = probe
    if not detect:
        reasons.setdefault(
            "detect", "Label-based poisoning detectors are disabled; only duplicate/outlier signals are fused."
        )
    quality = n_records > 0
    if not quality:
        reasons["quality"] = "No records were found."
    return Capabilities(labels=labels, security=True, quality=quality, probe=probe, detect=detect, reasons=reasons)
