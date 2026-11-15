"""Magic-byte sniffing: what a file *is*, regardless of what its name claims (F01).

``sniff(path, claimed_name)`` reads the first 4 KiB (plus, for ZIP containers, the
central directory and at most 1 MiB of ``[Content_Types].xml`` / ``mimetype``) and the
last 64 KiB. Nothing is decompressed beyond that and nothing is executed. It should
still run inside the isolated worker, because ZIP central-directory parsing is parsing.
"""

from __future__ import annotations

import os
import zipfile
from pathlib import Path

from pydantic import BaseModel, ConfigDict

from poisonlens.core.paths import os_path
from poisonlens.core.schemas import Finding, Location, Severity
from poisonlens.ingest.upload import stored_extension
from poisonlens.security.catalogue import make_finding

HEAD_BYTES = 4096
TAIL_BYTES = 65536
_MAX_ZIP_META = 1024 * 1024

ARCHIVE_KINDS = frozenset({"zip", "tar", "gzip", "bz2", "xz", "7z"})
EXECUTABLE_KINDS = frozenset({"pe", "elf", "macho", "jar"})
SERIALIZED_KINDS = frozenset({"pickle", "pytorch_zip", "zlib"})


class SniffResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    kind: str  # e.g. "zip", "xlsx", "parquet", "pe", "text", "unknown"
    confidence: float
    claimed_ext: str
    mismatch: bool
    detail: str = ""
    polyglot: bool = False  # another container's signature found where it should not be
    macro_enabled: bool = False


# (offset, magic, kind) — first match wins, so put more specific entries first.
_SIGNATURES: list[tuple[int, bytes, str]] = [
    (0, b"\x89PNG\r\n\x1a\n", "png"),
    (0, b"\xff\xd8\xff", "jpeg"),
    (0, b"GIF87a", "gif"),
    (0, b"GIF89a", "gif"),
    (0, b"II*\x00", "tiff"),
    (0, b"MM\x00*", "tiff"),
    (0, b"%PDF-", "pdf"),
    (0, b"\x1f\x8b", "gzip"),
    (0, b"BZh", "bz2"),
    (0, b"\xfd7zXZ\x00", "xz"),
    (0, b"7z\xbc\xaf\x27\x1c", "7z"),
    (0, b"PAR1", "parquet"),
    (0, b"ARROW1", "arrow"),
    (0, b"ORC", "orc"),
    (0, b"Obj\x01", "avro"),
    (0, b"\x89HDF\r\n\x1a\n", "hdf5"),
    (512, b"\x89HDF\r\n\x1a\n", "hdf5"),  # MATLAB v7.3 has a 512-byte text header
    (0, b"SQLite format 3\x00", "sqlite"),
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "ole2"),
    (0, b"\x93NUMPY", "npy"),
    (0, b"$FL2", "sav"),
    (0, b"$FL3", "sav"),
    (0, b"<stata_dta>", "dta"),
    (0, b"fLaC", "flac"),
    (0, b"OggS", "ogg"),
    (0, b"ID3", "mp3"),
    (0, b"\xff\xfb", "mp3"),
    (0, b"\xff\xf3", "mp3"),
    (0, b"\xff\xf2", "mp3"),
    (0, b"\x7fELF", "elf"),
    (0, b"\xfe\xed\xfa\xce", "macho"),
    (0, b"\xfe\xed\xfa\xcf", "macho"),
    (0, b"\xce\xfa\xed\xfe", "macho"),
    (0, b"\xcf\xfa\xed\xfe", "macho"),
    (0, b"\xca\xfe\xba\xbe", "macho"),  # universal binary (also Java class files)
    (0, b"MZ", "pe"),
    (0, b"\x00\x00\x08\x01", "idx"),
    (0, b"\x00\x00\x08\x03", "idx"),
    (0, b"PK\x03\x04", "zip"),
    (0, b"PK\x05\x06", "zip"),  # empty zip
]
_SAS7BDAT_MAGIC = bytes.fromhex("000000000000000000000000c2ea8160b31411cfbd92080009c7318c181f1011")

# Which sniffed kinds are acceptable for a claimed extension.
_TEXTY = {"text", "json", "xml"}
ALLOWED_KINDS: dict[str, set[str]] = {
    **{e: set(_TEXTY) for e in ("csv", "tsv", "txt", "psv", "json", "jsonl", "ndjson", "xml", "conll")},
    "xlsx": {"xlsx"},
    "xlsm": {"xlsx"},
    "xls": {"ole2"},
    "ods": {"ods"},
    "parquet": {"parquet"},
    "feather": {"arrow"},
    "arrow": {"arrow"},
    "orc": {"orc"},
    "avro": {"avro"},
    "sav": {"sav"},
    "dta": {"dta"},
    "sas7bdat": {"sas7bdat"},
    "npy": {"npy"},
    "npz": {"npz", "zip"},
    "h5": {"hdf5"},
    "hdf5": {"hdf5"},
    "mat": {"hdf5"},
    "sqlite": {"sqlite"},
    "db": {"sqlite"},
    "zip": {"zip", "npz"},
    "tar": {"tar"},
    "gz": {"gzip"},
    "tgz": {"gzip"},
    "tar.gz": {"gzip"},
    "bz2": {"bz2"},
    "tar.bz2": {"bz2"},
    "xz": {"xz"},
    "tar.xz": {"xz"},
    "7z": {"7z"},
    "png": {"png"},
    "jpg": {"jpeg"},
    "jpeg": {"jpeg"},
    "gif": {"gif"},
    "bmp": {"bmp"},
    "tif": {"tiff"},
    "tiff": {"tiff"},
    "webp": {"webp"},
    "wav": {"wav"},
    "flac": {"flac"},
    "ogg": {"ogg"},
    "mp3": {"mp3"},
    "pkl": {"pickle"},
    "pickle": {"pickle"},
    "joblib": {"pickle", "zlib"},
    "pt": {"pytorch_zip", "pickle"},
    "pth": {"pytorch_zip", "pickle"},
    "tfrecord": {"unknown"},  # no magic number; validated by the adapter
}


def _read_head_tail(path: Path) -> tuple[bytes, bytes, int]:
    size = os.path.getsize(os_path(path))
    with open(os_path(path), "rb") as fh:
        head = fh.read(HEAD_BYTES)
        if size > TAIL_BYTES:
            fh.seek(size - TAIL_BYTES)
        else:
            fh.seek(0)
        tail = fh.read(TAIL_BYTES)
    return head, tail, size


def _riff_kind(head: bytes) -> str | None:
    if head[:4] == b"RIFF" and len(head) >= 12:
        return {b"WAVE": "wav", b"WEBP": "webp"}.get(head[8:12])
    return None


def _looks_like_pickle(head: bytes) -> bool:
    # Protocol 2+ starts with PROTO opcode 0x80 <version>; ends with STOP '.'.
    return len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5


def _text_kind(head: bytes) -> str | None:
    if not head:
        return "text"
    sample = head
    for bom, enc in ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be")):
        if sample.startswith(bom):
            sample = sample[len(bom) :]
            try:
                text = sample.decode(enc, errors="strict")
            except UnicodeDecodeError:
                text = sample[: len(sample) - (len(sample) % 2)].decode(enc, errors="replace")
            break
    else:
        if b"\x00" in sample:
            return None
        text = sample.decode("utf-8", errors="replace")
    if not text:
        return "text"
    bad = sum(1 for ch in text if ch == "�" or (ord(ch) < 32 and ch not in "\t\r\n\f"))
    if bad / len(text) > 0.05:
        return None
    stripped = text.lstrip()
    if stripped.startswith(("{", "[")):
        return "json"
    if stripped.startswith("<"):
        return "xml"
    return "text"


def _zip_kind(path: Path) -> tuple[str, str, bool]:
    """Distinguish OOXML / ODF / NumPy npz / PyTorch / JAR from a plain ZIP."""
    try:
        with zipfile.ZipFile(os_path(path)) as zf:
            infos = zf.infolist()
            names = [i.filename for i in infos]
            by_name = {i.filename: i for i in infos}
            if "[Content_Types].xml" in by_name and by_name["[Content_Types].xml"].file_size <= _MAX_ZIP_META:
                ct = zf.read("[Content_Types].xml").decode("utf-8", errors="replace")
                macro = "macroEnabled" in ct or any(n.lower().endswith("vbaproject.bin") for n in names)
                if "spreadsheetml" in ct or "ms-excel" in ct:
                    return "xlsx", "OOXML spreadsheet", macro
                if "wordprocessingml" in ct:
                    return "docx", "OOXML document", macro
                if "presentationml" in ct:
                    return "pptx", "OOXML presentation", macro
                return "ooxml", "OOXML package", macro
            if "mimetype" in by_name and by_name["mimetype"].file_size <= 256:
                mt = zf.read("mimetype").decode("ascii", errors="replace").strip()
                if mt == "application/vnd.oasis.opendocument.spreadsheet":
                    return "ods", "OpenDocument spreadsheet", False
                return "odf", f"OpenDocument ({mt})", False
            if "META-INF/MANIFEST.MF" in by_name:
                return "jar", "Java archive", False
            if names and all(n.endswith(".npy") for n in names):
                return "npz", "NumPy npz", False
            if any(n == "data.pkl" or n.endswith("/data.pkl") for n in names):
                return "pytorch_zip", "PyTorch zip checkpoint", False
            return "zip", f"ZIP archive, {len(names)} entries", False
    except (zipfile.BadZipFile, OSError, ValueError) as exc:
        return "zip", f"ZIP signature but unreadable central directory: {exc}", False


def sniff(path: Path, claimed_name: str) -> SniffResult:
    """Identify ``path`` by content and compare with the extension of ``claimed_name``."""
    head, tail, size = _read_head_tail(path)
    claimed_ext = stored_extension(claimed_name)
    kind, confidence, detail, macro = "unknown", 0.0, "", False

    if size >= 264 and head[257:262] == b"ustar":
        kind, confidence, detail = "tar", 1.0, "POSIX tar"
    elif len(head) >= 32 and head[:32] == _SAS7BDAT_MAGIC:
        kind, confidence = "sas7bdat", 1.0
    elif (riff := _riff_kind(head)) is not None:
        kind, confidence = riff, 1.0
    elif head[:2] == b"BM" and len(head) >= 14 and int.from_bytes(head[2:6], "little") in (size, 0):
        kind, confidence = "bmp", 0.9
    elif _looks_like_pickle(head):
        kind, confidence, detail = "pickle", 0.9, f"pickle protocol {head[1]}"
    elif head[:1] == b"\x78" and len(head) > 1 and head[1] in (0x01, 0x5E, 0x9C, 0xDA):
        kind, confidence, detail = "zlib", 0.6, "zlib stream (e.g. compressed joblib)"
    else:
        for offset, magic, sig_kind in _SIGNATURES:
            if head[offset : offset + len(magic)] == magic:
                kind, confidence = sig_kind, 1.0
                break
        else:
            text_kind = _text_kind(head)
            if text_kind is not None:
                kind, confidence = text_kind, 0.6

    if kind == "zip":
        kind, detail, macro = _zip_kind(path)

    # A ZIP end-of-central-directory record at the end of a non-ZIP file means a second
    # container is appended (e.g. image+zip polyglot). OOXML/npz/etc are ZIPs themselves.
    zip_family = kind in {"zip", "xlsx", "docx", "pptx", "ooxml", "ods", "odf", "jar", "npz", "pytorch_zip"}
    polyglot = not zip_family and b"PK\x05\x06" in tail and kind not in {"unknown"}

    allowed = ALLOWED_KINDS.get(claimed_ext)
    if kind in EXECUTABLE_KINDS:
        mismatch = True
    elif allowed is None:
        mismatch = True  # extension not on the allowlist
    else:
        mismatch = kind not in allowed and not (kind == "unknown" and "unknown" in allowed)

    return SniffResult(
        kind=kind,
        confidence=confidence,
        claimed_ext=claimed_ext,
        mismatch=mismatch,
        detail=detail,
        polyglot=polyglot,
        macro_enabled=macro,
    )


def f01_findings(result: SniffResult, location: str) -> list[Finding]:
    """F01: disguised / polyglot / non-allowlisted files. Empty list when consistent."""
    loc = Location(file=location)
    findings: list[Finding] = []
    if result.kind in EXECUTABLE_KINDS:
        findings.append(
            make_finding(
                "F01",
                f"Executable content ({result.kind.upper()}) disguised as .{result.claimed_ext}",
                severity=Severity.HIGH,
                detail="The file's signature bytes identify an executable, not a dataset.",
                evidence={"sniffed_kind": result.kind, "claimed_ext": result.claimed_ext},
                location=loc,
                remediation="Do not open this file. Obtain the dataset from a trusted source.",
            )
        )
    elif result.mismatch:
        known = result.claimed_ext in ALLOWED_KINDS
        findings.append(
            make_finding(
                "F01",
                f"Content does not match extension .{result.claimed_ext}"
                if known
                else f"Extension .{result.claimed_ext} is not on the allowlist",
                severity=Severity.HIGH if result.kind in SERIALIZED_KINDS | ARCHIVE_KINDS else Severity.MEDIUM,
                detail=f"Signature bytes identify '{result.kind}'"
                + (f" ({result.detail})" if result.detail else "")
                + ".",
                evidence={
                    "sniffed_kind": result.kind,
                    "claimed_ext": result.claimed_ext,
                    "confidence": result.confidence,
                },
                location=loc,
                remediation="Rename the file to its real type or re-export it in a supported format.",
            )
        )
    if result.polyglot:
        findings.append(
            make_finding(
                "F01",
                "Polyglot file: a ZIP archive is appended after the main content",
                severity=Severity.HIGH,
                evidence={"sniffed_kind": result.kind},
                location=loc,
                remediation="Re-export the data; appended containers are a common smuggling technique.",
            )
        )
    return findings
