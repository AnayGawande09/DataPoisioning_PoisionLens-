"""FastAPI server for PoisonLens v2.

The upload-first scan API (spec section 6) is built in Phase 10; until then
only the health endpoint is served. See docs/MIGRATION_NOTES.md for the v1
endpoints that were removed.
"""

from __future__ import annotations

from typing import Any, Dict

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from poisonlens import __version__

app = FastAPI(
    title="PoisonLens API",
    description="Upload a dataset, audit it for poisoning, and get a sanitized, audited copy back.",
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Strict local origins only (configurable CORS arrives with the Phase 10 config).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key", "Last-Event-ID"],
)


@app.get("/api/health", summary="Service health")
def health() -> Dict[str, Any]:
    """Report that the API is up and which version is running."""
    import torch

    return {
        "status": "healthy",
        "service": "PoisonLens",
        "version": __version__,
        "torch_device": "cuda" if torch.cuda.is_available() else "cpu",
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
