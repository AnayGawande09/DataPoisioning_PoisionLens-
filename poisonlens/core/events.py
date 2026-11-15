"""Progress events and the per-scan append-only ``events.jsonl`` log.

The pipeline process is the single writer for a scan's event log; the API reads it
(possibly while it is being written) to serve SSE with ``Last-Event-ID`` replay.
An event's id is its 0-based line number, so ids are stable and need no counter.
A trailing line without ``\\n`` is an in-progress write and is not returned yet.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Iterator
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from poisonlens.core.schemas import StageName, utc_now


class EventKind(str, Enum):
    STAGE_START = "stage_start"
    PROGRESS = "progress"
    LOG = "log"
    METRIC = "metric"
    STAGE_END = "stage_end"
    ERROR = "error"


class ProgressEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    stage: StageName | None = None  # None for scan-level events
    kind: EventKind
    payload: dict[str, Any] = Field(default_factory=dict)
    ts: datetime = Field(default_factory=utc_now)


class EventLog:
    """Append-only JSONL event log for one scan."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, event: ProgressEvent) -> None:
        """Append one event as a single ``write`` of one complete line, then flush + fsync."""
        line = event.model_dump_json() + "\n"
        if "\n" in line[:-1]:  # pydantic JSON never contains raw newlines; guard anyway
            raise ValueError("event serialized to more than one line")
        data = line.encode("utf-8")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with open(self.path, "ab") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())

    def emit(self, scan_id: str, kind: EventKind, stage: StageName | None = None, **payload: Any) -> None:
        """Convenience wrapper: build and append a :class:`ProgressEvent`."""
        self.append(ProgressEvent(scan_id=scan_id, stage=stage, kind=kind, payload=payload))

    def iter_from(self, after_id: int | None = None) -> Iterator[tuple[int, ProgressEvent]]:
        """Yield ``(event_id, event)`` for complete lines with id > ``after_id`` (all if None)."""
        if not self.path.exists():
            return
        start = -1 if after_id is None else after_id
        with open(self.path, "rb") as fh:
            for idx, raw in enumerate(fh):
                if not raw.endswith(b"\n"):
                    return  # partial line still being written
                if idx <= start:
                    continue
                yield idx, ProgressEvent.model_validate(json.loads(raw.decode("utf-8")))

    def read_all(self) -> list[ProgressEvent]:
        return [ev for _, ev in self.iter_from()]
