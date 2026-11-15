"""Builders for hostile and benign archives. Everything is generated in-test; nothing is committed.

No fixture contains real malware: "executables" are just the 2-byte ``MZ`` signature plus padding.
"""

from __future__ import annotations

import gzip
import io
import stat
import tarfile
import zipfile
from pathlib import Path

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
FAKE_PE = b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + b"\x00" * 200


def write_zip(path: Path, members: list[tuple[str, bytes]], *, symlinks: dict[str, str] | None = None) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)
        for name, target in (symlinks or {}).items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3  # unix, so external_attr mode bits are meaningful
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, target)
    return path


def zip_bytes(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def nested_zip(path: Path, depth: int) -> Path:
    """``depth`` levels of ZIP: level 1 is the file at ``path``; the innermost holds data.csv."""
    payload = zip_bytes([("data.csv", b"a,b\n1,2\n")])
    for level in range(depth - 1, 0, -1):
        payload = zip_bytes([(f"level{level + 1}.zip", payload)])
    path.write_bytes(payload)
    return path


def write_tar(path: Path, members: list[tarfile.TarInfo | tuple[str, bytes]], mode: str = "w:gz") -> Path:
    with tarfile.open(path, mode) as tf:
        for m in members:
            if isinstance(m, tarfile.TarInfo):
                tf.addfile(m)
            else:
                name, data = m
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return path


def tar_special(name: str, kind: bytes, linkname: str = "") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    return info


def zeros_zip_bomb(path: Path, total: int = 1024**3, block: int = 1024 * 1024) -> Path:
    """One member of ``total`` zero bytes (1 GiB by default), deflated to ~1 MiB, written streaming."""
    zero = bytes(block)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
        with zf.open("zeros.csv", "w", force_zip64=True) as fh:
            for _ in range(total // block):
                fh.write(zero)
    return path


def zeros_gzip_bomb(path: Path, total: int = 1024**3, block: int = 1024 * 1024) -> Path:
    """A single-file gzip of zeros: no declared size anywhere, only streaming caps can stop it."""
    zero = bytes(block)
    with gzip.open(path, "wb", compresslevel=1) as fh:
        for _ in range(total // block):
            fh.write(zero)
    return path
