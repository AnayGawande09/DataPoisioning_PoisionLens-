"""Filename analysis and sanitization for uploads and archive members (F03 / F04).

``analyze_member_path`` classifies every problem as either

* **unsafe** (F03, critical): the path could write outside the extraction root —
  absolute, drive letter, UNC, or a ``..`` component. Never extracted.
* **hygiene** (F04, medium): the name is legal but dangerous or ambiguous — NUL /
  control / bidi characters, Windows-reserved device names, characters Windows
  forbids, trailing dots or spaces, over-long components. Fixed by sanitizing,
  except NUL which makes the name untrustworthy and causes the member to be skipped.

Sanitized paths use ``/`` separators, NFC normalization and only safe characters,
so they are portable between Windows and POSIX.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from dataclasses import dataclass, field

BIDI_CONTROLS = frozenset("‪‫‬‭‮⁦⁧⁨⁩‎‏؜")
WINDOWS_FORBIDDEN = frozenset('<>:"|?*')
WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
)
MAX_COMPONENT_BYTES = 200  # leaves room for suffixes we add; NTFS/ext4 allow 255
_DRIVE_RE = re.compile(r"^[A-Za-z]:")


@dataclass
class NameCheck:
    raw: str
    sanitized: str | None  # None => must not be extracted
    unsafe: list[str] = field(default_factory=list)  # F03 reasons
    hygiene: list[str] = field(default_factory=list)  # F04 reasons

    @property
    def ok(self) -> bool:
        return self.sanitized is not None


def _shorten(component: str) -> str:
    data = component.encode("utf-8")
    if len(data) <= MAX_COMPONENT_BYTES:
        return component
    digest = hashlib.sha256(data).hexdigest()[:12]
    stem, dot, ext = component.rpartition(".")
    keep_ext = f".{ext}" if dot and len(ext) <= 10 else ""
    budget = MAX_COMPONENT_BYTES - len(digest) - len(keep_ext) - 1
    head = (stem if keep_ext else component).encode("utf-8")[:budget].decode("utf-8", "ignore")
    return f"{head}~{digest}{keep_ext}"


def _sanitize_component(comp: str, hygiene: list[str]) -> str:
    out = []
    for ch in comp:
        if ch in BIDI_CONTROLS:
            hygiene.append("bidi control character")
        elif unicodedata.category(ch) in ("Cc", "Cf"):
            hygiene.append(f"control/format character U+{ord(ch):04X}")
        elif ch in WINDOWS_FORBIDDEN:
            hygiene.append(f"character {ch!r} not allowed on Windows")
            out.append("_")
        else:
            out.append(ch)
    clean = "".join(out)
    stripped = clean.rstrip(" .")
    if stripped != clean:
        hygiene.append("trailing dot or space")
        clean = stripped
    if clean.split(".")[0].upper() in WINDOWS_RESERVED:
        hygiene.append(f"reserved Windows device name {clean.split('.')[0]!r}")
        clean = "_" + clean
    short = _shorten(clean)
    if short != clean:
        hygiene.append("over-long name component")
    return short


def analyze_member_path(raw: str, max_total_length: int = 1024) -> NameCheck:
    """Validate and sanitize one archive member path (or an uploaded file name)."""
    check = NameCheck(raw=raw, sanitized=None)
    if "\x00" in raw:
        check.hygiene.append("NUL byte in name")
        return check  # untrustworthy: different tools truncate at different places

    name = unicodedata.normalize("NFC", raw).replace("\\", "/")
    if name.startswith("/"):
        check.unsafe.append("absolute path" if not name.startswith("//") else "UNC path")
    if _DRIVE_RE.match(name):
        check.unsafe.append("drive-letter path")
    parts = [p for p in name.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        check.unsafe.append("parent-directory traversal ('..')")
    if check.unsafe:
        return check
    if not parts:
        check.hygiene.append("empty name")
        return check

    hygiene: list[str] = []
    clean_parts = [_sanitize_component(p, hygiene) for p in parts]
    if any(p == "" for p in clean_parts):
        hygiene.append("component empty after sanitizing")
        check.hygiene = sorted(set(hygiene))
        return check
    sanitized = "/".join(clean_parts)
    if len(sanitized) > max_total_length:
        hygiene.append("path longer than limit")
        check.hygiene = sorted(set(hygiene))
        return check
    check.hygiene = sorted(set(hygiene))
    check.sanitized = sanitized
    return check


def collision_key(sanitized: str) -> str:
    """Key under which two names collide on a case-insensitive filesystem (Windows, macOS default)."""
    return unicodedata.normalize("NFC", sanitized).casefold()
