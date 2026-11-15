"""Gate 2: the isolated worker returns results via file and kills runaway jobs (Windows + Linux)."""

from __future__ import annotations

import time

import pytest

from poisonlens.core.config import MiB, WorkerLimits
from poisonlens.ingest.worker import run_isolated

ALLOW = ("tests.unit.worker_jobs:",)
FAST = WorkerLimits(max_memory_bytes=1024 * MiB, wall_clock_seconds=60, cpu_seconds=60, poll_interval_seconds=0.1)


def _run(func, tmp_path, limits=FAST, args=None):
    return run_isolated(f"tests.unit.worker_jobs:{func}", args or {}, limits, tmp_path, allowed_prefixes=ALLOW)


def test_returns_value(tmp_path):
    res = _run("echo", tmp_path, args={"x": [1, 2]})
    assert res.ok and not res.killed
    assert res.value == {"echo": {"x": [1, 2]}, "answer": 42}
    assert res.exit_code == 0
    assert list(tmp_path.glob(".worker_result_*")) == []  # result file cleaned up


def test_reports_exception(tmp_path):
    res = _run("fail", tmp_path, args={"why": "test"})
    assert not res.ok and not res.killed
    assert res.error_type == "ValueError" and "deliberate failure: test" in res.error_message


def test_hard_exit_without_result(tmp_path):
    res = _run("hard_exit", tmp_path)
    assert not res.ok and res.error_type == "WorkerCrashed" and res.exit_code == 3


def test_wall_clock_kill(tmp_path):
    limits = FAST.model_copy(update={"wall_clock_seconds": 3.0})
    t0 = time.monotonic()
    res = _run("sleep_forever", tmp_path, limits)
    elapsed = time.monotonic() - t0
    assert res.killed and res.kill_reason == "wall_clock"
    assert 3.0 <= res.wall_seconds < 3.0 + 5.0  # killed within one poll + process teardown
    assert elapsed < 15


def test_cpu_time_kill(tmp_path):
    limits = FAST.model_copy(update={"cpu_seconds": 2.0, "wall_clock_seconds": 30.0})
    res = _run("spin_forever", tmp_path, limits)
    assert not res.ok
    # Windows: psutil watchdog. POSIX: RLIMIT_CPU may deliver SIGXCPU first -> crash without result.
    assert (res.killed and res.kill_reason == "cpu_time") or res.error_type == "WorkerCrashed"
    assert res.wall_seconds < 20


def test_memory_kill(tmp_path):
    limits = FAST.model_copy(update={"max_memory_bytes": 300 * MiB, "wall_clock_seconds": 60.0})
    res = _run("eat_memory", tmp_path, limits)
    assert not res.ok
    # Windows: watchdog kills on RSS. POSIX: RLIMIT_AS may raise MemoryError in the child first.
    assert (res.killed and res.kill_reason == "memory") or res.error_type == "MemoryError"
    assert res.wall_seconds < 30


@pytest.mark.parametrize("func", ["open_socket", "run_subprocess", "os_system"])
def test_network_and_process_spawning_blocked(tmp_path, func):
    res = _run(func, tmp_path)
    assert not res.ok
    assert res.error_type == "BlockedOperationError", res


def test_target_must_be_allowlisted(tmp_path):
    with pytest.raises(ValueError, match="allowed prefix"):
        run_isolated("os:system", {}, FAST, tmp_path)
    with pytest.raises(ValueError):
        run_isolated("tests.unit.worker_jobs:echo", {}, FAST, tmp_path)  # default prefix is poisonlens.


def test_args_must_be_json(tmp_path):
    with pytest.raises(TypeError):
        _run("echo", tmp_path, args={"x": object()})
