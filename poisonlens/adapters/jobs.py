"""S1 jobs, executed inside the isolated worker (``ingest.worker.run_isolated``).

* ``inspect_job`` — choose an adapter, profile the dataset (sampled), write ``canonical/profile.json``.
* ``load_job`` — with the user's :class:`Selection`, stream the CDR into ``canonical/`` and
  rewrite ``profile.json`` with exact counts (``sampled=False``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from poisonlens.adapters.base import Source, write_json
from poisonlens.adapters.registry import adapter_for_profile, choose_adapter
from poisonlens.core.config import ScanConfig
from poisonlens.core.errors import UnsafeFileError
from poisonlens.core.events import EventKind, EventLog
from poisonlens.core.paths import ScanPaths
from poisonlens.core.schemas import DatasetProfile, Selection, SplitInfo, StageName
from poisonlens.ingest.sniff import ARCHIVE_KINDS


def source_for_scan(paths: ScanPaths) -> Source:
    """The S1 input: the extracted sandbox for archives, otherwise the stored upload."""
    report_path = paths.results / "ingest_report.json"
    if not report_path.exists():
        raise UnsafeFileError("S0 ingestion has not run for this scan")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("halted"):
        raise UnsafeFileError(f"upload was rejected in S0: {report.get('halt_reason')}")
    meta = json.loads((paths.upload / "meta.json").read_text(encoding="utf-8"))
    kind = report["sniff"]["kind"]
    if kind in ARCHIVE_KINDS:
        return Source(path=paths.sandbox, kind="directory", name=meta["original_name"], payload_prefix="sandbox")
    return Source(
        path=paths.resolve(meta["stored_path"]), kind=kind, name=meta["original_name"], self_ref=meta["stored_path"]
    )


def _ctx(args: dict[str, Any]) -> tuple[ScanConfig, ScanPaths, EventLog]:
    cfg = ScanConfig.model_validate(args.get("config") or {})
    paths = ScanPaths(args["scan_id"], data_dir=Path(args["data_dir"]))
    return cfg, paths, EventLog(paths.events_file)


def inspect_job(args: dict[str, Any]) -> dict[str, Any]:
    cfg, paths, events = _ctx(args)
    events.emit(paths.scan_id, EventKind.STAGE_START, StageName.INSPECT)
    src = source_for_scan(paths)
    adapter = choose_adapter(src)
    selection = Selection.model_validate(args["selection"]) if args.get("selection") else None
    profile = adapter.inspect(src, cfg, selection)
    write_json(paths.canonical / "profile.json", profile.model_dump(mode="json"))
    events.emit(
        paths.scan_id,
        EventKind.STAGE_END,
        StageName.INSPECT,
        status="profiled",
        adapter=profile.adapter,
        modality=profile.modality.value,
        n_records=profile.n_records,
    )
    return profile.model_dump(mode="json")


def load_job(args: dict[str, Any]) -> dict[str, Any]:
    cfg, paths, events = _ctx(args)
    profile = DatasetProfile.model_validate_json((paths.canonical / "profile.json").read_text(encoding="utf-8"))
    selection = Selection.model_validate(args.get("selection") or {})
    src = source_for_scan(paths)
    adapter = adapter_for_profile(profile)
    events.emit(paths.scan_id, EventKind.PROGRESS, StageName.INSPECT, step="load", adapter=profile.adapter)
    result = adapter.load(src, profile, selection, paths.canonical, cfg)
    splits = None
    if result.split_counts:
        column = profile.splits.column if profile.splits else "split"
        splits = SplitInfo(column=column, counts=result.split_counts)
    final = profile.model_copy(
        update={
            "n_records": result.n_records,
            "class_hist": result.class_hist if profile.label_chosen else {},
            "splits": splits,
            "sampled": False,
            "warnings": profile.warnings + result.warnings,
        }
    )
    write_json(paths.canonical / "profile.json", final.model_dump(mode="json"))
    events.emit(paths.scan_id, EventKind.STAGE_END, StageName.INSPECT, status="loaded", n_records=result.n_records)
    return {"n_records": result.n_records, "label_names": result.label_names, "artifacts": result.artifacts}
