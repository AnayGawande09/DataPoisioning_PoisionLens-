"""Scan ledger: SHA-256 hash-chained ``audit/ledger.jsonl`` (spec S7).

Entry: ``{i, ts, type, payload, prev, hash}`` with
``hash = SHA256(prev || canonical_json({i, ts, type, payload}))``.

Phase 2 status: this is the minimal append path used by ingestion. Phase 9 adds
process-safe atomic append (file lock), verification against artifacts, the
Tier 1 Merkle root and the Ed25519 seal; the entry format here is already final.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from enum import Enum
from pathlib import Path
from typing import Any

from poisonlens.core.schemas import utc_now

GENESIS_HASH = "0" * 64


class EntryType(str, Enum):
    SCAN_STARTED = "SCAN_STARTED"
    FILE_ACCEPTED = "FILE_ACCEPTED"
    FILE_REJECTED = "FILE_REJECTED"
    SECURITY_FINDING = "SECURITY_FINDING"
    STAGE_COMPLETED = "STAGE_COMPLETED"
    SAMPLE_DECISION = "SAMPLE_DECISION"
    USER_OVERRIDE = "USER_OVERRIDE"
    CANARY_RESULT = "CANARY_RESULT"
    EXPORT_CREATED = "EXPORT_CREATED"
    SCAN_SEALED = "SCAN_SEALED"


def canonical_json(obj: Any) -> str:
    """Sorted keys, no whitespace, UTF-8 kept: equivalent payloads always hash identically."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def entry_hash(prev: str, body: dict[str, Any]) -> str:
    return hashlib.sha256((prev + canonical_json(body)).encode("utf-8")).hexdigest()


class Ledger:
    """Append-only hash chain for one scan."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def _head(self) -> tuple[int, str]:
        if not self.path.exists():
            return 0, GENESIS_HASH
        last = None
        with open(self.path, "rb") as fh:
            for raw in fh:
                if raw.strip():
                    last = raw
        if last is None:
            return 0, GENESIS_HASH
        entry = json.loads(last)
        return int(entry["i"]) + 1, str(entry["hash"])

    def append(self, entry_type: EntryType, payload: dict[str, Any]) -> dict[str, Any]:
        """Append one entry and return it (including its hash)."""
        with self._lock:
            i, prev = self._head()
            body = {"i": i, "ts": utc_now().isoformat(), "type": entry_type.value, "payload": payload}
            entry = {**body, "prev": prev, "hash": entry_hash(prev, body)}
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "ab") as fh:
                fh.write((canonical_json(entry) + "\n").encode("utf-8"))
                fh.flush()
                os.fsync(fh.fileno())
            return entry

    def entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with open(self.path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]
