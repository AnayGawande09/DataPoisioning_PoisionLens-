"""Job functions run by tests/unit/test_ingest_worker.py inside the isolated worker.

Not a test module (no ``test_`` prefix), so pytest does not collect it; the spawned child imports it.
"""

from __future__ import annotations

import time
from typing import Any


def echo(args: dict[str, Any]) -> dict[str, Any]:
    return {"echo": args, "answer": 42}


def fail(args: dict[str, Any]) -> None:
    raise ValueError("deliberate failure: " + str(args.get("why")))


def sleep_forever(args: dict[str, Any]) -> None:
    while True:
        time.sleep(0.05)


def spin_forever(args: dict[str, Any]) -> None:
    x = 0
    while True:
        x += 1


def eat_memory(args: dict[str, Any]) -> None:
    hog = []
    while True:
        block = bytearray(16 * 1024 * 1024)
        for i in range(0, len(block), 4096):  # touch every page so it is really resident
            block[i] = 1
        hog.append(block)
        time.sleep(0.02)


def open_socket(args: dict[str, Any]) -> None:
    import socket

    socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def run_subprocess(args: dict[str, Any]) -> None:
    import subprocess

    subprocess.run(["python", "--version"], check=False)


def os_system(args: dict[str, Any]) -> None:
    import os

    os.system("echo hi")


def hard_exit(args: dict[str, Any]) -> None:
    import os

    os._exit(3)
