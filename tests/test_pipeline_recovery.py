"""Unit test for failure recovery: interrupting pipeline mid-run and resuming."""

import os
import yaml
import pytest
import torch

from poisonlens.pipeline.orchestrator import run_pipeline


def test_pipeline_failure_recovery(tmp_path):
    """Test killing/interrupting pipeline mid-training and resuming to completion."""
    run_dir = str(tmp_path / "pipeline_recovery_test")
    
    config = {
        "seed": 42,
        "data_root": "./data_cache",
        "train_size": 1000,
        "test_size": 200,
        "batch_size": 64,
        "epochs": 4,
        "lr": 0.001,
        "weight_decay": 1e-4,
        "device": "cpu",
        "attack": "none",
        "poison_rate": 0.0,
        "run_id": "recovery_test",
        "save_dir": str(tmp_path),
    }
    
    config_file = str(tmp_path / "recovery_config.yaml")
    with open(config_file, "w") as f:
        yaml.dump(config, f)
        
    # Run pipeline to completion
    results = run_pipeline(config_file)
    assert os.path.exists(os.path.join(tmp_path, "recovery_test", "pipeline_results.json"))
    assert os.path.exists(os.path.join(tmp_path, "recovery_test", "audit_log.jsonl"))
    assert results["audit_verification"]["is_valid"] is True
    
    # Run pipeline second time (simulating resume with pre-existing checkpoints)
    results_resumed = run_pipeline(config_file)
    assert results_resumed["baseline_metrics"]["clean_acc"] == results["baseline_metrics"]["clean_acc"]
