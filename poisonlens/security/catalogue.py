"""Security Check Catalogue metadata (spec section 3), shared by ingestion and the S2 engine.

Reference codes follow the spec's table. OWASP ML Top 10 = ``ML01``..``ML10``,
OWASP Top 10 for LLM Applications 2025 = ``LLM01``..``LLM05``, and
``FILE-UPLOAD-CS`` = OWASP File Upload Cheat Sheet. Implementers must re-verify
identifiers against the current published OWASP/ATLAS versions (spec section 3).
"""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass
from typing import Any

from poisonlens.core.schemas import Finding, Location, Severity

FILE_UPLOAD_CS = "FILE-UPLOAD-CS"


@dataclass(frozen=True)
class CheckInfo:
    check_id: str
    title: str
    default_severity: Severity
    owasp_refs: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()


_S = Severity
CATALOGUE: dict[str, CheckInfo] = {
    c.check_id: c
    for c in [
        # 3.1 File-level
        CheckInfo("F01", "Extension / magic-byte consistency", _S.MEDIUM, (FILE_UPLOAD_CS,), ("CWE-434",)),
        CheckInfo("F02", "Archive bomb limits", _S.HIGH, (), ("CWE-409",)),
        CheckInfo("F03", "Archive path safety", _S.CRITICAL, (), ("CWE-22", "CWE-59")),
        CheckInfo("F04", "Filename hygiene", _S.MEDIUM, (), ("CWE-176",)),
        CheckInfo("F05", "Embedded executables / scripts", _S.HIGH, ("ML06", "LLM03"), ()),
        CheckInfo("F06", "Malware scan", _S.CRITICAL, ("ML06",), ()),
        CheckInfo("F07", "Unsafe serialization", _S.CRITICAL, ("ML06", "LLM03"), ("CWE-502",)),
        CheckInfo("F08", "Office / Excel active content", _S.HIGH, (), ("CWE-94",)),
        CheckInfo("F09", "XML safety", _S.HIGH, (), ("CWE-611", "CWE-776")),
        CheckInfo("F10", "Spreadsheet / CSV formula injection", _S.MEDIUM, (), ("CWE-1236",)),
        CheckInfo("F11", "SQLite safety", _S.HIGH, (), ("CWE-89",)),
        CheckInfo("F12", "Image safety", _S.MEDIUM, (), ("CWE-434",)),
        CheckInfo("F13", "Audio / container anomalies", _S.LOW, (), ("CWE-20",)),
        CheckInfo("F14", "URL-indexed dataset", _S.HIGH, ("ML02", "LLM04", "ML06"), ()),
        # 3.2 Content-level
        CheckInfo("C01", "PII scan", _S.MEDIUM, ("LLM02", "ML03", "ML04"), ()),
        CheckInfo("C02", "Secrets scan", _S.HIGH, ("LLM02",), ()),
        CheckInfo("C03", "Prompt-injection / jailbreak patterns", _S.HIGH, ("LLM01", "LLM04"), ()),
        CheckInfo("C04", "Active content in text fields", _S.MEDIUM, ("LLM05",), ("CWE-79",)),
        CheckInfo("C05", "Invisible / encoding anomalies", _S.LOW, (), ("CWE-176",)),
        CheckInfo("C06", "Duplicates & conflicting-label duplicates", _S.MEDIUM, ("ML02", "ML04"), ()),
        CheckInfo("C07", "Cross-split leakage", _S.MEDIUM, ("ML08",), ()),
        CheckInfo("C08", "Label integrity", _S.LOW, ("ML02",), ()),
        CheckInfo("C09", "Provenance & insertion patterns", _S.MEDIUM, ("ML02", "ML08"), ()),
        CheckInfo("C10", "Outliers & shortcut features", _S.MEDIUM, ("ML02",), ()),
        CheckInfo("C11", "Trigger-candidate mining", _S.HIGH, ("ML02", "ML10"), ()),
    ]
}

_counter = itertools.count(1)
_counter_lock = threading.Lock()


def make_finding(
    check_id: str,
    title: str,
    *,
    detail: str = "",
    severity: Severity | None = None,
    evidence: dict[str, Any] | None = None,
    location: Location | None = None,
    remediation: str = "",
    finding_id: str | None = None,
) -> Finding:
    """Build a :class:`Finding` with the catalogue's default severity and references."""
    info = CATALOGUE[check_id]
    if finding_id is None:
        with _counter_lock:
            finding_id = f"{check_id}-{next(_counter):05d}"
    return Finding(
        id=finding_id,
        check_id=check_id,
        severity=severity or info.default_severity,
        title=title,
        detail=detail,
        evidence=evidence or {},
        location=location,
        owasp_refs=list(info.owasp_refs),
        cwe=list(info.cwe),
        remediation=remediation,
    )
