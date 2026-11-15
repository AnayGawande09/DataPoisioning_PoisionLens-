"""Ingestion jobs executed inside the isolated worker (see ``worker.run_isolated``).

``ingest_job`` is S0's untrusted-content step: sniff the stored upload (F01), expand
archives safely into ``sandbox/`` (F02/F03/F04), and persist ``results/ingest_report.json``
plus ``results/findings_ingest.json``. Findings are appended to the ledger, and the file
is recorded as rejected when a halting finding fires.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from poisonlens.audit.ledger import EntryType, Ledger
from poisonlens.core.config import ScanConfig
from poisonlens.core.paths import ScanPaths
from poisonlens.core.schemas import Finding, Severity
from poisonlens.ingest.archive import ExtractionReport, safe_extract
from poisonlens.ingest.sniff import ARCHIVE_KINDS, EXECUTABLE_KINDS, f01_findings, sniff


def ingest_job(args: dict[str, Any]) -> dict[str, Any]:
    """Args: ``scan_id``, ``data_dir``, optional ``config`` (ScanConfig dump). Returns a JSON summary."""
    cfg = ScanConfig.model_validate(args.get("config") or {})
    paths = ScanPaths(args["scan_id"], data_dir=Path(args["data_dir"]))
    meta = json.loads((paths.upload / "meta.json").read_text(encoding="utf-8"))
    original = paths.resolve(meta["stored_path"])
    original_name = meta["original_name"]

    result = sniff(original, original_name)
    findings: list[Finding] = f01_findings(result, original_name)
    report: ExtractionReport | None = None
    halted = result.kind in EXECUTABLE_KINDS
    halt_reason = "F01 executable content" if halted else None

    if not halted and result.kind in ARCHIVE_KINDS:
        report = safe_extract(
            original,
            result.kind,
            paths.sandbox,
            cfg.limits.archive,
            halt_on_critical=cfg.security.halt_on_critical_file,
            label=original_name,
        )
        findings.extend(report.findings)
        if report.halted:
            halted, halt_reason = True, report.halt_reason

    findings.sort(key=lambda f: f.severity.rank)
    paths.results.mkdir(parents=True, exist_ok=True)
    summary = {
        "sniff": result.model_dump(),
        "extraction": report.model_dump() if report else None,
        "halted": halted,
        "halt_reason": halt_reason,
        "n_findings": len(findings),
        "max_severity": findings[0].severity.value if findings else None,
    }
    (paths.results / "ingest_report.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    (paths.results / "findings_ingest.json").write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=2), encoding="utf-8"
    )

    ledger = Ledger(paths.audit / "ledger.jsonl")
    for f in findings:
        if f.severity is not Severity.INFO:
            ledger.append(
                EntryType.SECURITY_FINDING,
                {"finding_id": f.id, "check_id": f.check_id, "severity": f.severity.value, "title": f.title},
            )
    if halted:
        ledger.append(EntryType.FILE_REJECTED, {"original_name": original_name, "reason": halt_reason})
    return {k: summary[k] for k in ("halted", "halt_reason", "n_findings", "max_severity")} | {
        "kind": result.kind,
        "members": len(report.members) if report else 0,
    }
