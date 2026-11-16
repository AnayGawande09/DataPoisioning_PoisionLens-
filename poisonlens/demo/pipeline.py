"""Quick-demo pipeline: one synchronous call from uploaded bytes to a sealed report.

Real stages (Phases 0-3): chunked upload → S0 safe ingest (sniff, archive expansion) →
S1 inspect + load into the canonical dataset. Demo stand-ins (Phases 4-9, simplified):
content security checks, quality checks, trigger mining, out-of-fold label agreement +
outliers, tiering, sanitized export, risk score, ledger seal.

The jobs run in-process for speed; the product runs S0/S1 in the isolated worker.
"""

from __future__ import annotations

import csv
import hashlib
import json
import time
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from PIL import Image

from poisonlens.adapters.jobs import inspect_job, load_job
from poisonlens.audit.ledger import GENESIS_HASH, EntryType, Ledger, entry_hash
from poisonlens.core.config import ScanConfig, load_scan_config
from poisonlens.core.paths import ScanPaths, default_data_dir, os_path
from poisonlens.core.schemas import DatasetProfile, Finding, Modality, Severity, Verdict
from poisonlens.demo.content import RecordFlags, is_formula, mine_triggers, quality_checks, scan_text_cells
from poisonlens.demo.detect import DetectResult, detect, tabular_matrix, text_matrix
from poisonlens.ingest.jobs import ingest_job
from poisonlens.ingest.upload import UploadManager
from poisonlens.security.catalogue import make_finding

Progress = Callable[[str, str], None]
SEVERITY_POINTS = {Severity.CRITICAL: 100, Severity.HIGH: 70, Severity.MEDIUM: 35, Severity.LOW: 10, Severity.INFO: 0}
EXPORT_FILES = ("cleaned.csv", "review.csv", "report.json", "ledger.jsonl")


def _noop(stage: str, msg: str) -> None:
    pass


def _sha(path: Path) -> str:
    h = hashlib.sha256()
    with open(os_path(path), "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def verify_ledger(entries: list[dict[str, Any]]) -> bool:
    prev = GENESIS_HASH
    for e in entries:
        body = {k: e[k] for k in ("i", "ts", "type", "payload")}
        if e["prev"] != prev or entry_hash(prev, body) != e["hash"]:
            return False
        prev = e["hash"]
    return True


# --------------------------------------------------------------------------- upload


def upload_bytes(chunks: Iterable[bytes], filename: str, size: int, cfg: ScanConfig, data_dir: Path) -> str:
    um = UploadManager(cfg.limits.upload, data_dir=data_dir)
    session = um.init(filename, size)
    buf = b""
    n = 0
    for chunk in chunks:
        buf += chunk
        while len(buf) >= session.part_size and n < session.n_parts - 1:
            um.put_part(session.upload_id, n, buf[: session.part_size])
            buf = buf[session.part_size :]
            n += 1
    um.put_part(session.upload_id, n, buf)
    return um.complete(session.upload_id).scan_id


# --------------------------------------------------------------------------- record access


class Records:
    """The canonical dataset as frames indexed by record_id."""

    def __init__(self, paths: ScanPaths, profile: DatasetProfile, cfg: ScanConfig):
        self.paths = paths
        self.profile = profile
        man = pd.read_parquet(os_path(paths.canonical / "manifest.parquet"))
        self.truncated = len(man) > cfg.demo.max_records
        if self.truncated:
            man = man.sample(n=cfg.demo.max_records, random_state=cfg.seed).sort_index()
        self.manifest = man.set_index("record_id")
        feat_path = paths.canonical / "features_raw.parquet"
        self.feats: pd.DataFrame | None = None
        if feat_path.exists():
            f = pd.read_parquet(os_path(feat_path)).set_index("record_id")
            self.feats = f.loc[f.index.intersection(self.manifest.index)]
        self.label_column = profile.label_chosen
        self.text_column = profile.text_column
        self._arr: np.ndarray | None = None
        self._image_cache: tuple[np.ndarray, np.ndarray, pd.Series] | None = None

    @property
    def ids(self) -> list[str]:
        return [str(i) for i in self.manifest.index]

    @property
    def labels(self) -> pd.Series:
        return self.manifest["label_raw"].astype("string")

    def model_feats(self) -> pd.DataFrame | None:
        if self.feats is None:
            return None
        drop = [c for c in (self.label_column,) if c in self.feats.columns]
        return self.feats.drop(columns=drop)

    def payload_text(self, ref: str | None, limit: int = 20_000) -> str:
        if not ref or ref.startswith("array:"):
            return ""
        try:
            with open(os_path(self.paths.resolve(ref)), encoding="utf-8", errors="replace") as fh:
                return fh.read(limit)
        except OSError:
            return ""

    def texts(self) -> pd.Series | None:
        if self.feats is not None and self.text_column in (self.feats.columns if self.feats is not None else []):
            return self.feats[self.text_column].astype("string").rename(self.text_column)
        if self.feats is None and self.profile.modality is Modality.TEXT:
            refs = self.manifest["payload_ref"]
            return pd.Series([self.payload_text(r) for r in refs], index=self.manifest.index, name="text")
        return None

    def image(self, i: int, side: int) -> np.ndarray | None:
        ref = self.manifest["payload_ref"].iloc[i]
        try:
            if ref.startswith("array:"):
                if self._arr is None:
                    self._arr = np.load(os_path(self.paths.canonical / "array_images.npy"), mmap_mode="r")
                img = Image.fromarray(np.asarray(self._arr[int(ref[6:])]).squeeze())
            else:
                img = Image.open(os_path(self.paths.resolve(ref)))
                img.draft("RGB", (side * 4, side * 4))
            return np.asarray(img.convert("RGB").resize((side, side), Image.Resampling.BILINEAR), dtype=np.uint8)
        except (OSError, ValueError):
            return None

    def preview(self, rid: str) -> str:
        if self.feats is not None and rid in self.feats.index:
            row = self.feats.loc[rid]
            if self.text_column and self.text_column in row.index:
                return str(row[self.text_column])[:200]
            parts = [f"{c}={row[c]}" for c in row.index if c != self.label_column][:6]
            return ", ".join(parts)[:200]
        ref = str(self.manifest.at[rid, "payload_ref"])
        if self.profile.modality is Modality.TEXT:
            return self.payload_text(ref, 200)
        return ref

    def string_cells(self) -> Iterable[tuple[str, str, str]]:
        if self.feats is not None:
            for col in self.feats.columns:
                s = self.feats[col]
                if pd.api.types.is_string_dtype(s) or s.dtype == object:
                    for rid, v in s.dropna().items():
                        yield str(rid), str(col), str(v)
        elif self.profile.modality is Modality.TEXT:
            t = self.texts()
            if t is not None:
                for rid, v in t.items():
                    yield str(rid), "text", str(v)


# --------------------------------------------------------------------------- main entry


def run_demo_scan(
    chunks: Iterable[bytes],
    filename: str,
    size: int,
    *,
    data_dir: Path | None = None,
    profile_name: str = "quick",
    progress: Progress = _noop,
) -> dict[str, Any]:
    t0 = time.perf_counter()
    cfg = load_scan_config(profile_name)
    data_dir = Path(data_dir) if data_dir else default_data_dir()
    timings: dict[str, float] = {}

    def lap(name: str, start: float) -> float:
        timings[name] = round(time.perf_counter() - start, 3)
        return time.perf_counter()

    progress("upload", "Receiving file")
    scan_id = upload_bytes(chunks, filename, size, cfg, data_dir)
    paths = ScanPaths(scan_id, data_dir=data_dir)
    ledger = Ledger(paths.audit / "ledger.jsonl")
    args = {"scan_id": scan_id, "data_dir": str(data_dir), "config": cfg.model_dump(mode="json")}
    t = lap("upload", t0)

    progress("ingest", "Checking file type and expanding archives safely")
    ingest = ingest_job(args)
    findings: list[Finding] = [
        Finding.model_validate(f)
        for f in json.loads((paths.results / "findings_ingest.json").read_text(encoding="utf-8"))
    ]
    t = lap("ingest", t)
    base: dict[str, Any] = {"scan_id": scan_id, "filename": filename, "size": size, "ingest": ingest, "notes": []}
    if ingest["halted"]:
        return _finish(paths, cfg, ledger, base, findings, None, None, None, {}, [], timings, t0, halted=True)

    progress("inspect", "Detecting format and profiling the dataset")
    try:
        prof = DatasetProfile.model_validate(inspect_job(args))
        if prof.adapter == "serialized":
            findings.append(
                make_finding(
                    "F07",
                    "Serialized Python object file (pickle / joblib / torch) — not loaded",
                    detail="Loading this file would execute code chosen by whoever made it. It was scanned only.",
                    remediation="Ask for the data in a safe format (CSV, Parquet, NumPy without pickles).",
                )
            )
            return _finish(paths, cfg, ledger, base, findings, prof, None, None, {}, [], timings, t0, halted=True)
        load_job(args | {"selection": prof.selection.model_dump(mode="json")})
        prof = DatasetProfile.model_validate_json((paths.canonical / "profile.json").read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001 — demo: report the failure instead of a 500
        base["error"] = f"{type(e).__name__}: {e}"
        return _finish(paths, cfg, ledger, base, findings, None, None, None, {}, [], timings, t0, halted=False)
    t = lap("inspect", t)
    ledger.append(EntryType.STAGE_COMPLETED, {"stage": "inspect", "adapter": prof.adapter, "n_records": prof.n_records})

    rec = Records(paths, prof, cfg)
    progress("security", "Scanning content for injection, PII, secrets")
    sec_findings, flags = scan_text_cells(rec.string_cells(), cfg)
    findings += sec_findings
    t = lap("security", t)

    progress("quality", "Looking for duplicates, conflicting labels and triggers")
    labels = rec.labels if prof.label_chosen else None
    q_findings, q_flags = quality_checks(
        rec.model_feats() if rec.feats is not None else None, labels, cfg, rec.label_column
    )
    findings += q_findings
    _merge(flags, q_flags)
    triggers: list[dict[str, Any]] = []
    if labels is not None:
        trig_feats = rec.model_feats()
        if rec.profile.modality is Modality.IMAGE and trig_feats is None:
            trig_feats = image_data(rec, cfg)[2].to_frame()
        tr_findings, tr_flags, triggers = mine_triggers(trig_feats, rec.texts(), labels, cfg, rec.label_column)
        findings += tr_findings
        _merge(flags, tr_flags)
    t = lap("quality", t)

    det: DetectResult | None = None
    if labels is not None and prof.capabilities.labels:
        progress("detect", "Training a probe model to find mislabeled and planted records")
        try:
            det = _run_detector(rec, labels, cfg)
        except ValueError as e:
            base["notes"].append(f"Detector skipped: {e}")
        t = lap("detect", t)
    else:
        base["notes"].append(prof.capabilities.reasons.get("labels", "No label column; detection skipped."))
    for f in findings:
        if f.severity is not Severity.INFO and f.check_id not in ("F01", "F02", "F03", "F04"):
            ledger.append(
                EntryType.SECURITY_FINDING,
                {"finding_id": f.id, "check_id": f.check_id, "severity": f.severity.value, "title": f.title},
            )
    return _finish(paths, cfg, ledger, base, findings, prof, rec, det, flags, triggers, timings, t0, halted=False)


def _merge(a: RecordFlags, b: RecordFlags) -> None:
    for k, v in b.items():
        a.setdefault(k, []).extend(v)


def _corner_patches(gray: np.ndarray) -> str | None:
    """Uniform, high-contrast square in a corner: the classic visual backdoor patch."""
    side = gray.shape[0]
    k = max(2, side // 6)
    ref = float(np.median(gray))
    for name, (ys, xs) in {
        "bottom-right": (slice(-k, None), slice(-k, None)),
        "bottom-left": (slice(-k, None), slice(None, k)),
        "top-right": (slice(None, k), slice(-k, None)),
        "top-left": (slice(None, k), slice(None, k)),
    }.items():
        patch = gray[ys, xs]
        if patch.std() < 8 and abs(float(patch.mean()) - ref) > 60:
            return f"{'bright' if patch.mean() > ref else 'dark'} patch, {name}"
    return None


def image_data(rec: Records, cfg: ScanConfig) -> tuple[np.ndarray, np.ndarray, pd.Series]:
    """Per-image standardized grayscale pixels (colour-invariant) + corner-patch descriptors."""
    side = cfg.demo.image_side
    n = len(rec.ids)
    x = np.zeros((n, side * side), dtype=np.float32)
    ok = np.zeros(n, dtype=bool)
    patches: list[str | None] = [None] * n
    if rec._image_cache is not None:
        return rec._image_cache
    for i in range(n):
        img = rec.image(i, side * 2)
        if img is None:
            continue
        gray = img.astype(np.float32) @ np.array([0.299, 0.587, 0.114], dtype=np.float32)
        patches[i] = _corner_patches(gray)
        small = gray.reshape(side, 2, side, 2).mean((1, 3))
        x[i] = ((small - small.mean()) / (small.std() + 1e-6)).reshape(-1)
        ok[i] = True
    rec._image_cache = (x, ok, pd.Series(patches, index=rec.manifest.index, name="corner_patch", dtype="string"))
    return rec._image_cache


def _run_detector(rec: Records, labels: pd.Series, cfg: ScanConfig) -> DetectResult:
    ids = rec.ids
    if rec.profile.modality is Modality.IMAGE and rec.feats is None:
        x, ok, _patches = image_data(rec, cfg)
        lab = labels.where(pd.Series(ok, index=labels.index))
        return detect(ids, x, lab, cfg, "image")
    feats = rec.model_feats()
    if feats is not None and len(feats.columns):
        x = tabular_matrix(feats.loc[ids], rec.text_column, cfg)
        return detect(ids, x, labels.loc[ids], cfg, "text" if rec.text_column else "tabular")
    texts = rec.texts()
    if texts is not None:
        return detect(ids, text_matrix(texts.loc[ids], cfg), labels.loc[ids], cfg, "text")
    raise ValueError("no features available for this modality in the demo")


# --------------------------------------------------------------------------- tiers, export, seal


def _tiers(
    rec: Records, det: DetectResult | None, flags: RecordFlags, cfg: ScanConfig
) -> tuple[dict[str, str], dict[str, float], dict[str, list[str]], float]:
    ids = rec.ids
    n = len(ids)
    score = dict.fromkeys(ids, 0.0)
    reasons: dict[str, list[str]] = defaultdict(list)
    if det is not None:
        for i, rid in enumerate(det.record_ids):
            score[rid] = float(det.score[i])
            if det.label_suspect[i]:
                reasons[rid].append(
                    f"model predicts '{det.predicted[i]}' (labelled '{rec.labels.at[rid]}', "
                    f"P(given label)={det.p_given[i]:.2f})"
                )
            elif det.outlier[i] > 0.98:
                reasons[rid].append("statistical outlier")
    strong = {"C11": 0.95, "C06": 0.7, "C03": 0.65, "C02": 0.6, "C04": 0.55, "C06-dup": 0.3}
    for rid, hits in flags.items():
        if rid not in score:
            continue
        for cid, why in hits:
            score[rid] = max(score[rid], strong.get(cid, 0.3))
            if why not in reasons[rid]:
                reasons[rid].append(why)
    flagged = sorted((r for r in ids if score[r] >= 0.6), key=lambda r: -score[r])
    eps_raw = len(flagged) / max(1, n)
    eps = min(max(eps_raw, cfg.detect.contamination_min), cfg.detect.contamination_max)
    cap3 = int(np.ceil(min(eps, cfg.tiers.tier3_max_fraction) * n))
    tier = dict.fromkeys(ids, "keep")
    for r in flagged[:cap3]:
        tier[r] = "quarantine"
    rest = sorted((r for r in ids if tier[r] == "keep" and score[r] >= 0.3), key=lambda r: -score[r])
    cap2 = int(np.ceil(min(cfg.tiers.tier2_multiplier * eps, cfg.tiers.tier2_max_fraction) * n))
    for r in rest[:cap2]:
        tier[r] = "downweight"
    return tier, score, reasons, eps_raw


def _safe_cell(v: Any) -> Any:
    if isinstance(v, str) and is_formula(v):
        return "'" + v
    return v


def _export(
    paths: ScanPaths,
    rec: Records,
    tier: dict[str, str],
    score: dict[str, float],
    reasons: dict[str, list[str]],
    cfg: ScanConfig,
) -> dict[str, str]:
    out = paths.root / "export"
    out.mkdir(parents=True, exist_ok=True)
    w = {
        "keep": cfg.tiers.keep_weight,
        "downweight": cfg.tiers.downweight_weight,
        "quarantine": cfg.tiers.quarantine_weight,
    }
    keep_ids = [r for r in rec.ids if tier[r] != "quarantine"]
    if rec.feats is not None:
        clean = rec.feats.loc[keep_ids].copy()
        clean = clean.apply(lambda s: s.map(_safe_cell) if s.dtype == object or pd.api.types.is_string_dtype(s) else s)
    else:
        clean = rec.manifest.loc[keep_ids, ["payload_ref", "label_raw"]].rename(
            columns={"payload_ref": "file", "label_raw": "label"}
        )
    clean.insert(0, "record_id", clean.index)
    clean["sample_weight"] = [w[tier[r]] for r in keep_ids]
    clean.to_csv(os_path(out / "cleaned.csv"), index=False, quoting=csv.QUOTE_MINIMAL)

    review = [r for r in rec.ids if tier[r] != "keep"]
    pd.DataFrame(
        {
            "record_id": review,
            "tier": [tier[r] for r in review],
            "score": [round(score[r], 4) for r in review],
            "label": [rec.labels.at[r] if rec.profile.label_chosen else None for r in review],
            "reasons": ["; ".join(reasons.get(r, [])) for r in review],
            "preview": [_safe_cell(rec.preview(r)) for r in review],
        }
    ).sort_values("score", ascending=False).to_csv(os_path(out / "review.csv"), index=False)
    return {name: _sha(out / name) for name in ("cleaned.csv", "review.csv")}


def _risk(
    findings: list[Finding], eps_raw: float, triggers: list[dict[str, Any]], cfg: ScanConfig, halted: bool
) -> tuple[float, Verdict, dict[str, float]]:
    # poisoning evidence (C06 conflicts, C08 labels, C11 triggers) is scored by the other components
    sec = max((SEVERITY_POINTS[f.severity] for f in findings if f.check_id not in ("C06", "C08", "C11")), default=0)
    cont = min(1.0, eps_raw / cfg.demo.contamination_full_scale) * 100
    trig = 100.0 if triggers else 0.0
    d = cfg.demo
    parts = {
        "security": sec * d.risk_security_weight,
        "contamination": cont * d.risk_contamination_weight,
        "triggers": trig * d.risk_trigger_weight,
    }
    score = round(sum(parts.values()), 1)
    if halted:
        return 100.0, Verdict.UNSAFE_FILE, parts
    if score >= cfg.risk.likely_poisoned_threshold:
        v = Verdict.LIKELY_POISONED
    elif score >= cfg.risk.suspicious_threshold:
        v = Verdict.SUSPICIOUS
    else:
        v = Verdict.CLEAN
    return score, v, {k: round(x, 1) for k, x in parts.items()}


def _finish(
    paths: ScanPaths,
    cfg: ScanConfig,
    ledger: Ledger,
    base: dict[str, Any],
    findings: list[Finding],
    prof: DatasetProfile | None,
    rec: Records | None,
    det: DetectResult | None,
    flags: RecordFlags,
    triggers: list[dict[str, Any]],
    timings: dict[str, float],
    t0: float,
    *,
    halted: bool,
) -> dict[str, Any]:
    findings.sort(key=lambda f: f.severity.rank)
    report: dict[str, Any] = dict(base)
    eps_raw = 0.0
    artifacts: dict[str, str] = {}
    flagged_rows: list[dict[str, Any]] = []
    tier_counts: Counter[str] = Counter()
    if rec is not None and "error" not in base:
        t = time.perf_counter()
        tier, score, reasons, eps_raw = _tiers(rec, det, flags, cfg)
        tier_counts = Counter(tier.values())
        artifacts = _export(paths, rec, tier, score, reasons, cfg)
        ledger.append(EntryType.SAMPLE_DECISION, {"tiers": dict(tier_counts), "estimated_contamination": eps_raw})
        ledger.append(EntryType.EXPORT_CREATED, {"artifacts": artifacts})
        order = sorted((r for r in rec.ids if tier[r] != "keep"), key=lambda r: -score[r])[:200]
        flagged_rows = [
            {
                "record_id": r,
                "tier": tier[r],
                "score": round(score[r], 3),
                "label": rec.labels.at[r] if rec.profile.label_chosen else None,
                "predicted": det.predicted[det.record_ids.index(r)] if det else None,
                "reasons": reasons.get(r, []),
                "preview": rec.preview(r),
            }
            for r in order
        ]
        timings["sanitize"] = round(time.perf_counter() - t, 3)
    risk, verdict, parts = _risk(findings, eps_raw, triggers, cfg, halted)
    report.update(
        {
            "verdict": verdict.value,
            "risk_score": risk,
            "risk_parts": parts,
            "estimated_contamination": round(eps_raw, 4),
            "profile": prof.model_dump(mode="json") if prof else None,
            "findings": [f.model_dump(mode="json") for f in findings],
            "severity_counts": dict(Counter(f.severity.value for f in findings)),
            "triggers": triggers,
            "detector": None
            if det is None
            else {
                "method": det.method,
                "oof_accuracy": det.oof_accuracy,
                "label_suspects": int(det.label_suspect.sum()),
                "notes": det.notes,
            },
            "tiers": dict(tier_counts),
            "flagged": flagged_rows,
            "truncated": bool(rec.truncated) if rec else False,
            "timings": timings,
        }
    )
    report["timings"]["total"] = round(time.perf_counter() - t0, 3)
    report_path = paths.results / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    body = json.dumps(report, indent=2, default=str)
    report_path.write_text(body, encoding="utf-8")
    sealed = ledger.append(
        EntryType.SCAN_SEALED,
        {"verdict": verdict.value, "risk_score": risk, "report_sha256": hashlib.sha256(body.encode()).hexdigest()},
    )
    export = paths.root / "export"
    export.mkdir(parents=True, exist_ok=True)
    (export / "report.json").write_text(body, encoding="utf-8")
    entries = ledger.entries()
    (export / "ledger.jsonl").write_bytes((paths.audit / "ledger.jsonl").read_bytes())
    report["ledger"] = {
        "entries": len(entries),
        "head": sealed["hash"],
        "verified": verify_ledger(entries),
        "types": [e["type"] for e in entries],
    }
    report["downloads"] = [n for n in EXPORT_FILES if (export / n).exists()]
    return report
