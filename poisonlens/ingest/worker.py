"""Run untrusted-input parsing in an isolated child process with resource limits.

``run_isolated("pkg.module:function", args, limits, workdir)`` starts a fresh
interpreter (``multiprocessing`` *spawn* — no inherited state), calls
``function(args) -> JSON-able``, and returns a :class:`WorkerResult`. The result
travels through a JSON file in ``workdir``; nothing is shared in memory.

Limits:

* **All platforms** — a parent-side ``psutil`` watchdog samples the child's process
  tree every ``poll_interval_seconds`` and kills it when RSS, CPU time or wall-clock
  time exceeds ``WorkerLimits``. This is the enforcement on Windows, where
  ``resource.setrlimit`` does not exist.
* **POSIX** — the child also sets ``RLIMIT_CPU`` and ``RLIMIT_AS`` on itself.
* **Linux** — the child tries to enter fresh user+network namespaces (no network
  interfaces); silently skipped where unprivileged namespaces are disabled.
* **No network / no process spawning** — the child installs a ``sys.addaudithook`` that
  raises on socket, subprocess, ``os.system``/``exec``/``spawn``/``startfile`` events.
  Job modules must not import networking code.

Only callables under ``allowed_prefixes`` (default ``poisonlens.``) can be targeted.
"""

from __future__ import annotations

import importlib
import json
import multiprocessing as mp
import os
import secrets
import sys
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict

from poisonlens.core.config import WorkerLimits

BLOCKED_AUDIT_PREFIXES = (
    "socket.",
    "subprocess.",
    "os.system",
    "os.exec",
    "os.posix_spawn",
    "os.spawn",
    "os.startfile",
    "os.fork",
    "os.forkpty",
    "pty.",
    "webbrowser.",
    "urllib.Request",
    "ftplib.",
    "smtplib.",
    "http.client.",
)


class WorkerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    value: Any = None
    error_type: str | None = None
    error_message: str | None = None
    killed: bool = False
    kill_reason: str | None = None  # "memory" | "cpu_time" | "wall_clock"
    exit_code: int | None = None
    wall_seconds: float = 0.0
    cpu_seconds: float = 0.0
    peak_rss_bytes: int = 0


class BlockedOperationError(RuntimeError):
    """Raised inside the worker when a job attempts network access or process creation."""


# --------------------------------------------------------------------------- child side


def _audit_hook(event: str, _args: tuple[Any, ...]) -> None:
    if event.startswith(BLOCKED_AUDIT_PREFIXES):
        raise BlockedOperationError(f"operation not permitted in the isolated worker: {event}")


def _apply_posix_limits(limits: dict[str, Any]) -> None:
    try:
        resource: Any = importlib.import_module("resource")  # POSIX only
    except ImportError:  # Windows: the psutil watchdog is the enforcement
        return
    cpu = int(limits["cpu_seconds"]) + 1
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 5))
    # Address space is much larger than RSS (thread stacks, mapped libraries), so allow headroom;
    # the psutil watchdog enforces the RSS limit precisely.
    mem = int(limits["max_memory_bytes"])
    as_limit = max(2 * mem, mem + 2 * 1024**3)
    try:
        resource.setrlimit(resource.RLIMIT_AS, (as_limit, as_limit))
    except (ValueError, OSError):
        pass


def _try_no_network_namespace() -> bool:
    unshare = getattr(os, "unshare", None)
    flags = getattr(os, "CLONE_NEWUSER", 0) | getattr(os, "CLONE_NEWNET", 0)
    if unshare is None or not flags:
        return False
    try:
        unshare(flags)
        return True
    except OSError:
        return False


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, default=str), encoding="utf-8")
    os.replace(tmp, path)


def _resolve(target: str) -> Callable[[dict[str, Any]], Any]:
    module_name, _, func_name = target.partition(":")
    if not module_name or not func_name:
        raise ValueError(f"target must be 'module:function', got {target!r}")
    module = importlib.import_module(module_name)
    func = getattr(module, func_name)
    if not callable(func):
        raise TypeError(f"{target} is not callable")
    return func


def _child_main(target: str, args: dict[str, Any], result_path: str, limits: dict[str, Any], workdir: str) -> None:
    out = Path(result_path)
    try:
        os.chdir(workdir)
        _apply_posix_limits(limits)
        netns = _try_no_network_namespace()
        func = _resolve(target)  # import before the hook so module init can load native libs
        sys.addaudithook(_audit_hook)
        value = func(args)
        _write_json_atomic(out, {"ok": True, "value": value, "netns": netns})
    except BaseException as exc:  # noqa: BLE001 - report everything, including MemoryError
        try:
            _write_json_atomic(
                out,
                {
                    "ok": False,
                    "error_type": type(exc).__name__,
                    "error_message": str(exc)[:2000],
                    "traceback": traceback.format_exc()[-4000:],
                },
            )
        except BaseException:  # noqa: BLE001, S110 - nowhere left to report; parent sees WorkerCrashed
            pass
        os._exit(1)


# --------------------------------------------------------------------------- parent side


def _tree_usage(proc: Any) -> tuple[int, float]:
    import psutil

    rss = 0
    cpu = 0.0
    procs = [proc]
    try:
        procs += proc.children(recursive=True)
    except psutil.Error:
        pass
    for p in procs:
        try:
            rss += p.memory_info().rss
            t = p.cpu_times()
            cpu += t.user + t.system
        except psutil.Error:
            continue
    return rss, cpu


def _kill_tree(proc: Any) -> None:
    import psutil

    try:
        children = proc.children(recursive=True)
    except psutil.Error:
        children = []
    for p in [*children, proc]:
        try:
            p.kill()
        except psutil.Error:
            pass


def run_isolated(
    target: str,
    args: dict[str, Any],
    limits: WorkerLimits,
    workdir: Path,
    *,
    allowed_prefixes: tuple[str, ...] = ("poisonlens.",),
) -> WorkerResult:
    """Run ``target(args)`` in a resource-limited child process. Never raises for job failures."""
    import psutil

    if not target.startswith(allowed_prefixes):
        raise ValueError(f"target {target!r} is not under an allowed prefix {allowed_prefixes}")
    json.dumps(args)  # args must be plain JSON (no pickled objects cross the boundary)
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    result_path = workdir / f".worker_result_{secrets.token_hex(6)}.json"

    ctx = mp.get_context("spawn")
    child = ctx.Process(
        target=_child_main,
        args=(target, args, str(result_path), limits.model_dump(), str(workdir)),
        daemon=True,
    )
    start = time.monotonic()
    child.start()
    try:
        ps = psutil.Process(child.pid) if child.pid is not None else None
    except psutil.NoSuchProcess:
        ps = None

    killed_reason: str | None = None
    peak_rss = 0
    cpu = 0.0
    while True:
        child.join(timeout=limits.poll_interval_seconds)
        wall = time.monotonic() - start
        if not child.is_alive():
            break
        if ps is not None:
            rss, cpu_now = _tree_usage(ps)
            peak_rss = max(peak_rss, rss)
            cpu = max(cpu, cpu_now)
            if rss > limits.max_memory_bytes:
                killed_reason = "memory"
            elif cpu > limits.cpu_seconds:
                killed_reason = "cpu_time"
        if killed_reason is None and wall > limits.wall_clock_seconds:
            killed_reason = "wall_clock"
        if killed_reason is not None:
            if ps is not None:
                _kill_tree(ps)
            child.kill()
            child.join(timeout=10)
            break

    wall = time.monotonic() - start
    base = {
        "exit_code": child.exitcode,
        "wall_seconds": round(wall, 3),
        "cpu_seconds": round(cpu, 3),
        "peak_rss_bytes": peak_rss,
    }
    try:
        if killed_reason is not None:
            return WorkerResult(
                ok=False,
                killed=True,
                kill_reason=killed_reason,
                error_type="LimitExceededError",
                error_message=f"worker killed: {killed_reason} limit exceeded",
                **base,
            )
        if not result_path.exists():
            return WorkerResult(
                ok=False,
                error_type="WorkerCrashed",
                error_message=f"worker exited with code {child.exitcode} without a result",
                **base,
            )
        data = json.loads(result_path.read_text(encoding="utf-8"))
        if data.get("ok"):
            return WorkerResult(ok=True, value=data.get("value"), **base)
        return WorkerResult(
            ok=False,
            error_type=data.get("error_type"),
            error_message=data.get("error_message"),
            **base,
        )
    finally:
        result_path.unlink(missing_ok=True)
        result_path.with_name(result_path.name + ".tmp").unlink(missing_ok=True)
