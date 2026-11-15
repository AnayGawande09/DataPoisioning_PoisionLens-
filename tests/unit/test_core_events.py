"""events.jsonl: append-only, replayable by id, tolerant of in-progress writes."""

import json
import threading

from poisonlens.core.events import EventKind, EventLog, ProgressEvent
from poisonlens.core.schemas import StageName

SCAN = "scan_0123abcd"


def test_append_and_replay(tmp_path):
    log = EventLog(tmp_path / "events.jsonl")
    log.emit(SCAN, EventKind.STAGE_START, StageName.INGEST)
    log.emit(SCAN, EventKind.PROGRESS, StageName.INGEST, done=5, total=10)
    log.emit(SCAN, EventKind.STAGE_END, StageName.INGEST, status="done")

    events = list(log.iter_from())
    assert [i for i, _ in events] == [0, 1, 2]
    assert events[1][1].payload == {"done": 5, "total": 10}
    assert [i for i, _ in log.iter_from(after_id=0)] == [1, 2]
    assert list(log.iter_from(after_id=2)) == []


def test_missing_file_is_empty(tmp_path):
    assert EventLog(tmp_path / "nope.jsonl").read_all() == []


def test_partial_trailing_line_is_ignored(tmp_path):
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    log.emit(SCAN, EventKind.LOG, message="first")
    with open(path, "ab") as fh:
        fh.write(b'{"scan_id": "scan_0123ab')  # writer mid-line
    assert [e.payload["message"] for e in log.read_all()] == ["first"]


def test_round_trip_and_utc(tmp_path):
    log = EventLog(tmp_path / "events.jsonl")
    ev = ProgressEvent(scan_id=SCAN, stage=StageName.PROBE, kind=EventKind.METRIC, payload={"epoch": 1, "loss": 0.5})
    log.append(ev)
    (back,) = log.read_all()
    assert back == ev
    assert back.ts.tzinfo is not None


def test_payload_with_newlines_stays_one_line(tmp_path):
    path = tmp_path / "events.jsonl"
    log = EventLog(path)
    log.emit(SCAN, EventKind.LOG, message="line1\nline2\r\n")
    lines = path.read_bytes().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["payload"]["message"] == "line1\nline2\r\n"


def test_concurrent_appends_produce_valid_lines(tmp_path):
    log = EventLog(tmp_path / "events.jsonl")

    def worker(n):
        for i in range(50):
            log.emit(SCAN, EventKind.PROGRESS, worker=n, i=i)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    events = log.read_all()
    assert len(events) == 200
    assert sorted((e.payload["worker"], e.payload["i"]) for e in events) == [
        (n, i) for n in range(4) for i in range(50)
    ]
