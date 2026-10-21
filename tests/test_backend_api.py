"""Comprehensive unit and integration tests for PoisonLens FastAPI backend."""

import os
import json
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.security import ALLOWED_PRESETS, ALLOWED_ARTIFACTS

client = TestClient(app)


def test_health_endpoint():
    """Verify health endpoint returns healthy status and platform metadata."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "PoisonLens Security Backend" in data["service"]
    assert "CIFAR-10" in data["platform"]
    assert set(data["supported_presets"]) == ALLOWED_PRESETS


def test_presets_valid():
    """Verify all 5 supported presets are returned with valid schema."""
    response = client.get("/api/presets")
    assert response.status_code == 200
    presets = response.json()
    assert len(presets) == 5
    preset_ids = {p["id"] for p in presets}
    assert preset_ids == ALLOWED_PRESETS

    for p in presets:
        assert p["dataset"] == "CIFAR-10"
        assert "SmallResNet" in p["model"]
        assert p["is_supported"] is True
        assert p["epochs"] >= 1
        assert p["batch_size"] == 128


def test_runs_list():
    """Verify runs directory scanning returns historical completed runs."""
    response = client.get("/api/runs")
    assert response.status_code == 200
    runs = response.json()
    assert isinstance(runs, list)
    assert len(runs) >= 5

    # Check that attack_badnets_5 exists
    badnets = next((r for r in runs if r["run_id"] == "attack_badnets_5"), None)
    assert badnets is not None
    assert badnets["status"] == "COMPLETED"
    assert badnets["attack_type"] == "badnets"
    assert badnets["baseline_clean_acc"] is not None


def test_start_experiment_invalid_preset():
    """Verify that unapproved or arbitrary presets are rejected with 400 Bad Request."""
    response = client.post(
        "/api/runs/start",
        json={"preset_name": "arbitrary_malicious_config"},
    )
    assert response.status_code == 400
    assert "not in the allowlist" in response.json()["detail"]


def test_start_experiment_validation_errors():
    """Verify missing preset name returns 400."""
    response = client.post("/api/runs/start", json={})
    assert response.status_code == 400
    assert "Either 'preset_name' or 'preset_id' must be specified" in response.json()["detail"]


def test_run_status_and_not_found():
    """Verify status polling for completed run and 404 for unknown run."""
    # Existing completed run
    response = client.get("/api/runs/attack_badnets_5/status")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "COMPLETED"
    assert data["stage_number"] == 6

    # Non-existent run
    response_404 = client.get("/api/runs/non_existent_run_9999/status")
    assert response_404.status_code == 404


def test_missing_result_artifacts():
    """Verify non-existent run results return 404."""
    response = client.get("/api/runs/unknown_run_xyz/results")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_real_results_schema():
    """Verify genuine pipeline_results.json schema and real metrics for attack_badnets_5."""
    response = client.get("/api/runs/attack_badnets_5/results")
    assert response.status_code == 200
    results = response.json()

    assert results["run_id"] == "attack_badnets_5"
    assert "config_hash" in results
    assert results["baseline_metrics"]["clean_acc"] == "57.85%"
    assert results["mitigated_metrics"]["clean_acc"] == "57.85%"
    assert results["baseline_metrics"]["asr"] == "91.67%"
    assert results["guardrail_decision"]["action"] == "ROLLBACK_TRIGGERED"
    assert results["audit_verification"]["is_valid"] is True


def test_sample_index_validation():
    """Verify sample index bounds checking and retrieval of genuine training dynamics."""
    # Negative sample index rejected by Pydantic validation (422)
    resp_neg = client.get("/api/runs/attack_badnets_5/samples/-1")
    assert resp_neg.status_code == 422

    # Out of range sample index rejected (400)
    resp_huge = client.get("/api/runs/attack_badnets_5/samples/999999")
    assert resp_huge.status_code == 400

    # Non-existent sample ID returns 404
    resp_missing = client.get("/api/runs/attack_badnets_5/samples/99999")
    assert resp_missing.status_code == 404

    # Valid sample ID (2984) returns real 10-epoch dynamics
    resp_valid = client.get("/api/runs/attack_badnets_5/samples/2984")
    assert resp_valid.status_code == 200
    sample = resp_valid.json()
    assert sample["sample_id"] == 2984
    assert sample["decision"] == "quarantine"
    assert sample["sample_weight"] == 0.0
    assert len(sample["loss_curve"]) == 10
    assert len(sample["preds_history"]) == 10
    assert len(sample["correct_history"]) == 10
    assert len(sample["reasons"]) > 0


def test_samples_filtering_and_pagination():
    """Verify sample search, pagination, and decision filtering."""
    # Quarantine filter
    resp_q = client.get("/api/runs/attack_badnets_5/samples?decision=quarantine&limit=10")
    assert resp_q.status_code == 200
    data_q = resp_q.json()
    assert len(data_q["items"]) <= 10
    for item in data_q["items"]:
        assert item["decision"] == "quarantine"
        assert item["sample_weight"] == 0.0

    # Ground truth poison filter
    resp_gt = client.get("/api/runs/attack_badnets_5/samples?ground_truth_only=true&limit=5")
    assert resp_gt.status_code == 200
    data_gt = resp_gt.json()
    for item in data_gt["items"]:
        assert item["is_ground_truth_poison"] is True


def test_audit_verification_real():
    """Verify real SHA-256 hash-chain verification passes on audit_log.jsonl."""
    response = client.post("/api/runs/attack_badnets_5/audit/verify")
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is True
    assert data["broken_index"] is None
    assert data["total_entries"] == 9800
    assert "SUCCESSFUL" in data["message"]


def test_audit_tamper_simulation():
    """Verify that tampered_audit_log.jsonl correctly flags cryptographic break at index 10."""
    response = client.post("/api/runs/attack_badnets_5/audit/simulate-tamper")
    assert response.status_code == 200
    data = response.json()
    assert data["is_valid"] is False
    assert data["broken_index"] == 10
    assert "TAMPERING DETECTED" in data["message"]


def test_path_traversal_rejection():
    """Verify path traversal sequences are rejected with 400 Bad Request."""
    # Path traversal in run_id
    resp1 = client.get("/api/runs/..%2F..%2Fetc/results")
    assert resp1.status_code in [400, 404]

    # Path traversal in artifact filename
    resp2 = client.get("/api/runs/attack_badnets_5/artifacts/..%2F..%2Fetc%2Fpasswd")
    assert resp2.status_code in [400, 404]


def test_artifact_listing_and_download():
    """Verify listing available safe artifacts and downloading permitted files."""
    # List artifacts
    resp_list = client.get("/api/runs/attack_badnets_5/artifacts")
    assert resp_list.status_code == 200
    artifacts = resp_list.json()
    filenames = {a["filename"] for a in artifacts}
    assert "pipeline_results.json" in filenames
    assert "audit_log.jsonl" in filenames
    assert "config.yaml" in filenames

    # Download permitted artifact
    resp_dl = client.get("/api/runs/attack_badnets_5/artifacts/config.yaml")
    assert resp_dl.status_code == 200
    assert "attack: \"badnets\"" in resp_dl.text or "attack: badnets" in resp_dl.text

    # Rejection of unauthorized artifact
    resp_unauth = client.get("/api/runs/attack_badnets_5/artifacts/arbitrary_file.sh")
    assert resp_unauth.status_code == 400
    assert "not accessible" in resp_unauth.json()["detail"]


def test_benchmarks_endpoint():
    """Verify master benchmark results table is returned."""
    response = client.get("/api/benchmarks")
    assert response.status_code == 200
    rows = response.json()
    assert len(rows) > 0
    attacks = {r["Attack"] for r in rows}
    assert "Label Flip (10%)" in attacks
    assert "BadNets Backdoor (5%)" in attacks
    assert "Blended Backdoor (5%)" in attacks
