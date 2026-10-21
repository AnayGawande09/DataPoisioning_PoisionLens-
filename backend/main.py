"""FastAPI server for PoisonLens ML Security Platform.

Provides secure REST APIs for initiating asynchronous ML pipeline runs,
polling status, retrieving sample training dynamics, verifying SHA-256 audit logs,
and downloading safe experiment artifacts.
"""

import os
from typing import Optional, Dict, Any, List
from fastapi import FastAPI, HTTPException, Query, Path, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from backend.security import (
    validate_run_id,
    validate_preset_name,
    validate_artifact_name,
    ALLOWED_PRESETS,
    ALLOWED_ARTIFACTS,
)
from backend.services import (
    get_all_presets,
    list_completed_runs,
    get_run_details,
    get_run_results_data,
    get_run_samples,
    get_sample_detail,
    verify_audit_log_file,
    get_audit_entries_paginated,
    get_master_benchmarks,
    get_run_artifacts_list,
    get_safe_artifact_file_path,
)
from backend.runner import pipeline_manager

app = FastAPI(
    title="PoisonLens ML Security API",
    description="Machine Learning Data Poisoning Detection & Mitigation Research API for CIFAR-10 / SmallResNet",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for frontend origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class StartExperimentRequest(BaseModel):
    preset_name: Optional[str] = Field(None, description="Preset name from allowlist (e.g. 'attack_badnets_5')")
    preset_id: Optional[str] = Field(None, description="Preset ID alias from allowlist")
    seed: Optional[int] = Field(default=None, description="Random seed for deterministic data splits")
    epochs: Optional[int] = Field(default=None, ge=1, le=50, description="Training epochs (1 to 50)")
    custom_run_id: Optional[str] = Field(default=None, description="Optional custom unique run ID")
    overrides: Optional[Dict[str, Any]] = Field(default=None, description="Optional parameter overrides")

    def get_preset_name(self) -> str:
        name = self.preset_name or self.preset_id
        if not name:
            raise HTTPException(status_code=400, detail="Either 'preset_name' or 'preset_id' must be specified.")
        return validate_preset_name(name)


@app.get("/api/health", summary="Service Health and Platform Details")
def health():
    """Verify backend availability, version, and platform configuration."""
    return {
        "status": "healthy",
        "service": "PoisonLens Security Backend",
        "version": "0.1.0",
        "platform": "CIFAR-10 / SmallResNet ML Security Pipeline",
        "supported_presets": sorted(list(ALLOWED_PRESETS)),
    }


@app.get("/api/presets", summary="List Supported Attack Configurations")
def get_presets():
    """List all supported research configurations and their metadata."""
    return get_all_presets()


@app.get("/api/runs", summary="List Completed and Historical Runs")
def list_runs():
    """Scan the runs/ directory and return all available experiment summaries."""
    return list_completed_runs()


@app.post("/api/runs/start", status_code=status.HTTP_202_ACCEPTED, summary="Start Asynchronous Experiment")
def start_experiment(req: StartExperimentRequest):
    """Launch an asynchronous pipeline run executing the CLI pipeline in a background worker."""
    preset = req.get_preset_name()
    seed = req.seed
    epochs = req.epochs

    if req.overrides:
        if seed is None and "seed" in req.overrides:
            seed = req.overrides["seed"]
        if epochs is None and "epochs" in req.overrides:
            epochs = req.overrides["epochs"]

    try:
        tracker = pipeline_manager.start_pipeline(
            preset_name=preset,
            seed=seed,
            epochs=epochs,
            custom_run_id=req.custom_run_id,
        )
        return tracker.to_dict()
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to start experiment: {str(e)}")


@app.post("/api/runs", status_code=status.HTTP_202_ACCEPTED, summary="Start Experiment (Alias)")
def create_run_alias(req: StartExperimentRequest):
    """Alias for POST /api/runs/start."""
    return start_experiment(req)


@app.get("/api/runs/{run_id}/status", summary="Poll Experiment Run Status")
def get_run_status(run_id: str = Path(..., description="Unique experiment run ID")):
    """Retrieve execution status, current stage, elapsed runtime, and stdout logs."""
    validate_run_id(run_id)
    status_info = pipeline_manager.get_status(run_id)
    if not status_info:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found in active or completed jobs.")
    return status_info


@app.get("/api/jobs/{job_id}", summary="Poll Job by Job ID (Alias)")
def get_job_alias(job_id: str):
    """Alias for polling run status via job_id."""
    status_info = pipeline_manager.get_status(job_id)
    if not status_info:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found.")
    return status_info


@app.get("/api/runs/{run_id}/results", summary="Get Experiment Results")
def get_results(run_id: str = Path(..., description="Unique experiment run ID")):
    """Retrieve genuine pipeline_results.json containing clean accuracy, ASR, and guardrail decisions."""
    return get_run_results_data(run_id)


@app.get("/api/runs/{run_id}", summary="Get Full Run Details")
def get_run(run_id: str = Path(..., description="Unique experiment run ID")):
    """Retrieve combined configuration, results, and summary for a run."""
    details = get_run_details(run_id)
    if not details:
        raise HTTPException(status_code=404, detail=f"Run '{run_id}' not found.")
    return details


@app.get("/api/runs/{run_id}/samples", summary="Search and Filter Samples")
def get_samples(
    run_id: str = Path(..., description="Unique experiment run ID"),
    limit: int = Query(50, ge=1, le=200, description="Items per page"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    decision: Optional[str] = Query(None, description="Filter: keep, downweight, quarantine"),
    min_score: Optional[float] = Query(None, description="Minimum suspicion score"),
    max_score: Optional[float] = Query(None, description="Maximum suspicion score"),
    search: Optional[str] = Query(None, description="Search by sample ID, reason, or hash"),
    ground_truth_only: bool = Query(False, description="Controlled-evaluation: show ground-truth poisons only"),
):
    """Query per-sample trajectory scores, decisions, weights, and detection reasons."""
    return get_run_samples(
        run_id=run_id,
        limit=limit,
        offset=offset,
        decision=decision,
        min_score=min_score,
        max_score=max_score,
        search=search,
        ground_truth_only=ground_truth_only,
    )


@app.get("/api/runs/{run_id}/samples/{sample_id}", summary="Get Single Sample Dynamics")
def get_sample(
    run_id: str = Path(..., description="Unique experiment run ID"),
    sample_id: int = Path(..., ge=0, description="Sample index within the dataset"),
):
    """Retrieve per-sample epoch-by-epoch loss trajectory, prediction history, and correctness trace."""
    detail = get_sample_detail(run_id, sample_id)
    if not detail:
        raise HTTPException(status_code=404, detail=f"Sample '{sample_id}' not found in run '{run_id}'.")
    return detail


@app.get("/api/runs/{run_id}/audit", summary="Get Paginated Audit Log Entries")
def get_audit(
    run_id: str = Path(..., description="Unique experiment run ID"),
    limit: int = Query(25, ge=1, le=100, description="Entries per page"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
):
    """Retrieve sequential cryptographic audit log blocks."""
    return get_audit_entries_paginated(run_id, limit=limit, offset=offset)


@app.post("/api/runs/{run_id}/audit/verify", summary="Verify Cryptographic Hash Chain Integrity")
def verify_audit(run_id: str = Path(..., description="Unique experiment run ID")):
    """Run real SHA-256 hash-chain verification over audit_log.jsonl."""
    return verify_audit_log_file(run_id, use_tampered=False)


@app.post("/api/runs/{run_id}/audit/simulate-tamper", summary="Simulate Tamper Verification Failure")
def simulate_tamper(run_id: str = Path(..., description="Unique experiment run ID")):
    """Verify tampered_audit_log.jsonl to test real-time tamper alert and broken link identification."""
    return verify_audit_log_file(run_id, use_tampered=True)


@app.get("/api/runs/{run_id}/artifacts", summary="List Available Run Artifacts")
def list_artifacts(run_id: str = Path(..., description="Unique experiment run ID")):
    """List all available safe artifact files for the specified run."""
    return get_run_artifacts_list(run_id)


@app.get("/api/runs/{run_id}/artifacts/{artifact_name}", summary="Download Permitted Run Artifact")
def download_artifact(
    run_id: str = Path(..., description="Unique experiment run ID"),
    artifact_name: str = Path(..., description="Filename of the artifact to download"),
):
    """Safely download an explicitly permitted artifact file (e.g. audit_log.jsonl, pipeline_results.json)."""
    file_path = get_safe_artifact_file_path(run_id, artifact_name)
    return FileResponse(file_path, filename=artifact_name)


@app.get("/api/benchmarks", summary="Get Master Empirical Benchmarks")
def get_benchmarks():
    """Retrieve empirical benchmark results across Undefended, Loss Filtering, Activation Clustering, and PoisonLens."""
    return get_master_benchmarks()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8000, reload=True)
