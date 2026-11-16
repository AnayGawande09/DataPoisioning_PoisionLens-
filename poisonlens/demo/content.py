"""Demo content checks (lightweight stand-ins for Phase 4/5): security patterns, quality, trigger mining.

Every check returns aggregate :class:`Finding` objects (masked evidence only) plus per-record
flags ``{record_id: [(check_id, reason)]}`` that the detector and the sanitizer consume.
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter, defaultdict
from collections.abc import Iterable
from typing import cast

import numpy as np
import pandas as pd

from poisonlens.core.config import ScanConfig
from poisonlens.core.schemas import Finding, Location, Severity
from poisonlens.security.catalogue import make_finding

RecordFlags = dict[str, list[tuple[str, str]]]

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
_NUMERIC = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$")

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "phone": re.compile(r"(?<!\w)\+?\d{1,3}[\s.-]?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\w)"),
    "card_number": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}
SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "api_key_assignment": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|passw(?:or)?d|token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/+]{12,}"
    ),
}
INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "ignore_instructions": re.compile(
        r"(?i)\b(?:ignore|disregard|forget)\s+(?:all\s+|any\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|prompts?|rules)"
    ),
    "role_override": re.compile(r"(?i)\byou\s+are\s+now\s+(?:a|an|in)\b|\bact\s+as\s+(?:an?\s+)?unrestricted"),
    "system_prompt_probe": re.compile(r"(?i)\b(?:reveal|print|show)\s+(?:your\s+|the\s+)?system\s+prompt"),
    "jailbreak_marker": re.compile(r"(?i)\b(?:jailbreak|DAN mode|developer mode enabled)\b"),
}
ACTIVE_CONTENT = re.compile(r"(?i)<\s*script\b|javascript\s*:|<\s*iframe\b|\bon(?:error|load|click)\s*=")
INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_'-]*")


def _luhn(digits: str) -> bool:
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def mask(value: str) -> str:
    """Never echo PII / secrets: keep a hint of shape only."""
    v = value.strip()
    if len(v) <= 4:
        return "****"
    return v[:2] + "*" * min(12, len(v) - 4) + v[-2:]


def is_formula(value: str) -> bool:
    return bool(value) and value.startswith(_FORMULA_START) and not _NUMERIC.match(value.strip())


class _Agg:
    """Accumulates hits for one check id."""

    def __init__(self, check_id: str):
        self.check_id = check_id
        self.records: set[str] = set()
        self.kinds: Counter[str] = Counter()
        self.samples: list[dict[str, str]] = []
        self.columns: Counter[str] = Counter()

    def hit(self, rid: str, kind: str, column: str, sample: str, flags: RecordFlags, reason: str, k: int) -> None:
        self.records.add(rid)
        self.kinds[kind] += 1
        self.columns[column] += 1
        if len(self.samples) < k:
            self.samples.append({"record_id": rid, "column": column, "kind": kind, "masked": sample})
        flags[rid].append((self.check_id, reason))


def scan_text_cells(cells: Iterable[tuple[str, str, str]], cfg: ScanConfig) -> tuple[list[Finding], RecordFlags]:
    """``cells`` yields ``(record_id, column, value)`` for every string value."""
    k = cfg.demo.findings_sample_size
    flags: RecordFlags = defaultdict(list)
    agg = {c: _Agg(c) for c in ("F10", "C01", "C02", "C03", "C04", "C05")}
    for rid, col, val in cells:
        if not val:
            continue
        if is_formula(val):
            agg["F10"].hit(rid, "formula", col, mask(val), flags, f"cell in '{col}' starts with a formula character", k)
        for kind, pat in PII_PATTERNS.items():
            for m in pat.finditer(val):
                if kind == "card_number" and not _luhn(m.group()):
                    continue
                agg["C01"].hit(rid, kind, col, mask(m.group()), flags, f"PII ({kind}) in '{col}'", k)
                break
        for kind, pat in SECRET_PATTERNS.items():
            hit = pat.search(val)
            if hit:
                agg["C02"].hit(rid, kind, col, mask(hit.group()), flags, f"secret ({kind}) in '{col}'", k)
        for kind, pat in INJECTION_PATTERNS.items():
            hit = pat.search(val)
            if hit:
                agg["C03"].hit(rid, kind, col, hit.group()[:60], flags, f"prompt-injection pattern ({kind})", k)
        active = ACTIVE_CONTENT.search(val)
        if active:
            agg["C04"].hit(rid, "markup", col, active.group()[:40], flags, f"active markup in '{col}'", k)
        invisible = INVISIBLE.search(val)
        if invisible:
            agg["C05"].hit(
                rid,
                "invisible_char",
                col,
                f"U+{ord(invisible.group()):04X}",
                flags,
                f"invisible / bidi characters in '{col}'",
                k,
            )

    text = {
        "F10": (
            "cells start with a spreadsheet formula character",
            "Exported CSV prefixes these cells with ' so spreadsheets show them as text.",
        ),
        "C01": ("records contain personal data", "Remove or pseudonymise the values before training; check consent."),
        "C02": ("records contain credentials or keys", "Revoke the credentials and drop the values from the data."),
        "C03": (
            "records contain prompt-injection / jailbreak phrasing",
            "Review these records; they can teach a model to obey injected instructions.",
        ),
        "C04": (
            "records contain active markup (script, javascript:)",
            "Strip markup or treat as plain text everywhere it is displayed.",
        ),
        "C05": (
            "records contain invisible or bidirectional control characters",
            "Normalise text (strip zero-width and bidi controls).",
        ),
    }
    findings = []
    for cid, a in agg.items():
        if not a.records:
            continue
        what, fix = text[cid]
        top_col = a.columns.most_common(1)[0][0]
        findings.append(
            make_finding(
                cid,
                f"{len(a.records)} {what}",
                detail=", ".join(f"{n}× {kind}" for kind, n in a.kinds.most_common()),
                evidence={"n_records": len(a.records), "by_kind": dict(a.kinds), "samples": a.samples},
                location=Location(column=top_col),
                remediation=fix,
            )
        )
    return findings, flags


def quality_checks(
    feats: pd.DataFrame | None, labels: pd.Series | None, cfg: ScanConfig, label_column: str | None
) -> tuple[list[Finding], RecordFlags]:
    """C06 duplicates / conflicting-label duplicates, C08 label integrity. Frames are indexed by record_id."""
    flags: RecordFlags = defaultdict(list)
    findings: list[Finding] = []
    k = cfg.demo.findings_sample_size
    if feats is not None and len(feats):
        cols = [c for c in feats.columns if c not in ("record_id", label_column)]
        if cols:
            body = feats[cols].round(cfg.quality.tabular_round_decimals)
            keys = pd.util.hash_pandas_object(body.astype(str), index=False)
            groups = keys.groupby(keys).groups
            dup_ids: list[str] = []
            conflict_ids: list[str] = []
            for _, idx in groups.items():
                if len(idx) < 2:
                    continue
                rids = [str(r) for r in idx]
                group_labels = labels.loc[idx].astype("string") if labels is not None else None
                if group_labels is not None and group_labels.nunique(dropna=True) > 1:
                    vc = group_labels.value_counts()
                    majority = vc.index[0] if vc.iloc[0] > vc.iloc[1] else None  # tie: every copy is suspect
                    for r, lab in zip(rids, group_labels, strict=True):
                        if lab != majority:
                            conflict_ids.append(r)
                            flags[r].append(("C06", "identical record appears elsewhere with a different label"))
                else:
                    dup_ids.extend(rids[1:])
                    for r in rids[1:]:
                        flags[r].append(("C06-dup", "exact duplicate of an earlier record"))
            if conflict_ids:
                findings.append(
                    make_finding(
                        "C06",
                        f"{len(conflict_ids)} records disagree with identical copies on the label",
                        severity=Severity.HIGH,
                        detail="The same inputs appear with different labels — a classic label-flipping signature.",
                        evidence={"n_records": len(conflict_ids), "samples": conflict_ids[:k]},
                        remediation="Keep at most one copy with the verified label.",
                    )
                )
            if dup_ids:
                findings.append(
                    make_finding(
                        "C06",
                        f"{len(dup_ids)} exact duplicate records",
                        severity=Severity.LOW,
                        evidence={"n_records": len(dup_ids), "samples": dup_ids[:k]},
                        remediation="Drop duplicates; repeated records over-weight their label.",
                    )
                )
        missing = feats.isna().mean()
        bad = missing[missing > 0.2]
        if len(bad):
            findings.append(
                make_finding(
                    "C08",
                    f"{len(bad)} columns are more than 20% empty",
                    severity=Severity.INFO,
                    evidence={"missing_fraction": {str(c): round(float(v), 3) for c, v in bad.items()}},
                )
            )
    if labels is not None:
        counts = labels.dropna().astype(str).value_counts()
        if len(counts) >= 2:
            ratio = counts.iloc[0] / max(1, counts.iloc[-1])
            if ratio >= cfg.quality.imbalance_ratio_warn:
                findings.append(
                    make_finding(
                        "C08",
                        f"Classes are imbalanced {ratio:.0f}:1",
                        evidence={"class_counts": {str(a): int(b) for a, b in counts.items()}},
                        remediation="Rebalance or use class weights; tiny classes are easy to poison.",
                    )
                )
            tiny = counts[counts < cfg.quality.tiny_class_min_support]
            if len(tiny):
                findings.append(
                    make_finding(
                        "C08",
                        f"{len(tiny)} classes have fewer than {cfg.quality.tiny_class_min_support} records",
                        evidence={"classes": {str(a): int(b) for a, b in tiny.items()}},
                    )
                )
    return findings, flags


def _support(n: int, cfg: ScanConfig) -> int:
    return max(cfg.quality.trigger_min_support_abs, int(cfg.quality.trigger_min_support_frac * n))


def mine_triggers(
    feats: pd.DataFrame | None,
    texts: pd.Series | None,
    labels: pd.Series,
    cfg: ScanConfig,
    label_column: str | None,
) -> tuple[list[Finding], RecordFlags, list[dict[str, object]]]:
    """C11 (frames indexed by record_id): rare tokens / exact cell values that almost always come
    with one label (backdoor triggers)."""
    flags: RecordFlags = defaultdict(list)
    lab = labels.astype("string")
    n = int(lab.notna().sum())
    if n == 0:
        return [], flags, []
    prior = lab.value_counts(normalize=True)
    min_sup = _support(n, cfg)
    q, d = cfg.quality, cfg.demo
    cands: list[dict[str, object]] = []

    def consider(kind: str, where: str, value: str, idx: pd.Index) -> None:
        sub = lab.loc[idx].dropna()
        if len(sub) < min_sup or len(sub) / n > d.trigger_max_value_frac:
            return
        top = sub.value_counts()
        cls, cnt = str(top.index[0]), int(top.iloc[0])
        purity = cnt / len(sub)
        if purity >= q.trigger_min_purity and purity / float(prior.get(cls, 1.0)) >= d.trigger_min_lift:
            cands.append(
                {
                    "kind": kind,
                    "where": where,
                    "value": value,
                    "target_label": cls,
                    "support": len(sub),
                    "purity": round(purity, 4),
                    "_idx": idx,
                }
            )

    if texts is not None:
        docs = texts.fillna("").astype(str).str.lower()
        index: dict[str, list[int]] = defaultdict(list)
        for i, doc in zip(docs.index, docs, strict=True):
            for tok in set(_TOKEN.findall(doc[:5000])):
                index[tok].append(i)
        for tok, rows in index.items():
            if len(rows) >= min_sup:
                consider("token", str(texts.name or "text"), tok, pd.Index(rows))
    if feats is not None:
        for col in feats.columns:
            if col in ("record_id", label_column) or (texts is not None and col == texts.name):
                continue
            s = feats[col].dropna()
            groups = s.groupby(s.astype(str)).groups
            continuous = s.dtype.kind in "iuf" and len(groups) > 50
            floor = float(np.median([len(i) for i in groups.values()])) * d.trigger_continuous_repeat if groups else 0.0
            for val, idx in groups.items():
                # in a continuous column, only a value repeated far more often than its neighbours can be a trigger
                if continuous and len(idx) < floor:
                    continue
                consider("cell_value", str(col), str(val), pd.Index(idx))

    cands.sort(key=lambda c: (-cast(float, c["purity"]), -cast(int, c["support"])))
    cands = cands[: q.trigger_top_k]
    findings = []
    public = []
    for c in cands:
        idx = cast(pd.Index, c.pop("_idx"))
        public.append(c)
        rids = idx.tolist()
        for r in rids:
            flags[str(r)].append(
                ("C11", f"carries trigger candidate {c['kind']} '{c['value']}' → '{c['target_label']}'")
            )
    if public:
        top = public[0]
        findings.append(
            make_finding(
                "C11",
                f"{len(public)} backdoor trigger candidate(s); strongest: '{top['value']}' → '{top['target_label']}'",
                detail=f"'{top['value']}' appears in {top['support']} records and "
                f"{cast(float, top['purity']) * 100:.1f}% of them are labelled '{top['target_label']}'.",
                evidence={"candidates": public},
                location=Location(column=str(top["where"])),
                remediation="Quarantine the records that carry the trigger and re-verify their labels.",
            )
        )
    return findings, flags, public


def row_hash(values: Iterable[object]) -> str:
    h = hashlib.sha256()
    for v in values:
        h.update(str(v).encode("utf-8", "replace") + b"\x1f")
    return h.hexdigest()
