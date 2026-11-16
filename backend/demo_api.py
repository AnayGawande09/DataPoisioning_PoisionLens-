"""Quick-demo API: upload a dataset (or pick a sample) and get the sealed report back.

Synchronous on purpose (the demo datasets scan in a few seconds); the product API with
resumable uploads and SSE progress is Phase 10.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response

from poisonlens.core.config import load_scan_config
from poisonlens.core.errors import PathSafetyError, PoisonLensError
from poisonlens.core.paths import ScanPaths, default_data_dir
from poisonlens.demo.pipeline import EXPORT_FILES, run_demo_scan
from poisonlens.demo.samples import SAMPLES, build

router = APIRouter()
STATIC = Path(__file__).parent / "static"
_CHUNK = 1 << 20
_MEDIA = {".csv": "text/csv", ".json": "application/json", ".jsonl": "application/x-ndjson", ".zip": "application/zip"}


@router.get("/", response_class=HTMLResponse, include_in_schema=False)
def index() -> HTMLResponse:
    html = (STATIC / "demo.html").read_text(encoding="utf-8")
    return HTMLResponse(
        html,
        headers={
            "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:"
        },
    )


@router.get("/api/demo/samples", summary="Sample datasets with planted problems")
def samples() -> list[dict[str, str]]:
    return [{"name": k, "description": v} for k, v in SAMPLES.items()]


@router.get("/api/demo/samples/{name}", summary="Download a sample dataset")
def sample_file(name: str) -> Response:
    if name not in SAMPLES:
        raise HTTPException(404, "unknown sample")
    data, _ = build(name)
    return Response(
        data,
        media_type=_MEDIA.get(Path(name).suffix, "application/octet-stream"),
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


def _chunks(fh: BinaryIO) -> Iterator[bytes]:
    yield from iter(lambda: fh.read(_CHUNK), b"")


@router.post("/api/demo/scan", summary="Upload a dataset and scan it")
def scan_upload(file: UploadFile = File(...)) -> dict[str, Any]:
    fh = file.file
    fh.seek(0, 2)
    size = fh.tell()
    fh.seek(0)
    limit = load_scan_config("quick").limits.upload.max_upload_bytes
    if size == 0:
        raise HTTPException(400, "empty file")
    if size > limit:
        raise HTTPException(413, f"file is larger than the {limit // (1 << 20)} MB limit")
    try:
        return run_demo_scan(_chunks(fh), file.filename or "upload.bin", size)
    except PoisonLensError as e:  # filename / upload validation
        raise HTTPException(400, str(e)) from e


@router.post("/api/demo/scan-sample/{name}", summary="Scan one of the bundled samples")
def scan_sample(name: str) -> dict[str, Any]:
    if name not in SAMPLES:
        raise HTTPException(404, "unknown sample")
    data, truth = build(name)
    report = run_demo_scan([data], name, len(data))
    report["planted_truth"] = {k: v for k, v in truth.items() if not isinstance(v, list)} | {
        k: len(v) for k, v in truth.items() if isinstance(v, list)
    }
    return report


def _scan_paths(scan_id: str) -> ScanPaths:
    try:
        paths = ScanPaths(scan_id, data_dir=default_data_dir())
    except PathSafetyError as e:
        raise HTTPException(400, "invalid scan id") from e
    if not paths.root.exists():
        raise HTTPException(404, "scan not found")
    return paths


@router.get("/api/demo/scans/{scan_id}/download/{name}", summary="Download an export artifact")
def download(scan_id: str, name: str) -> FileResponse:
    if name not in EXPORT_FILES:
        raise HTTPException(404, "unknown artifact")
    path = _scan_paths(scan_id).root / "export" / name
    if not path.is_file():
        raise HTTPException(404, "artifact not produced for this scan")
    return FileResponse(
        path, media_type=_MEDIA.get(path.suffix, "application/octet-stream"), filename=f"{scan_id}_{name}"
    )
