"""Unit tests for hash-chained audit logging and tamper verification."""

import os
import json
import pytest

from poisonlens.audit.log import HashChainedAuditLog, verify_audit_log


def test_audit_log_creation_and_verification(tmp_path):
    log_file = str(tmp_path / "test_audit.jsonl")
    audit = HashChainedAuditLog(log_file, config_hash="test_config_hash_123")
    
    # Log 5 decisions
    for i in range(5):
        audit.log_decision(
            sample_id=100 + i,
            score=0.5 * i,
            reasons=[f"Reason {i}"],
            decision="quarantine" if i >= 3 else "keep",
            sample_weight=0.0 if i >= 3 else 1.0,
        )
        
    assert os.path.exists(log_file)
    with open(log_file, "r") as f:
        lines = f.readlines()
    assert len(lines) == 5
    
    # Verification must pass
    is_valid, bad_idx, msg = verify_audit_log(log_file)
    assert is_valid is True
    assert bad_idx is None
    assert "SUCCESSFUL" in msg


def test_audit_log_tamper_detection(tmp_path):
    log_file = str(tmp_path / "tampered_audit.jsonl")
    audit = HashChainedAuditLog(log_file, config_hash="config_abc")
    
    for i in range(4):
        audit.log_decision(
            sample_id=i,
            score=1.0 * i,
            reasons=[f"Reason {i}"],
            decision="keep",
            sample_weight=1.0,
        )
        
    # Read entries, tamper with entry index 2 (change score from 2.0 to 999.0)
    with open(log_file, "r") as f:
        entries = [json.loads(line) for line in f]
        
    entries[2]["score"] = 999.0
    
    with open(log_file, "w") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")
            
    # Verification must detect tampering on entry 2
    is_valid, bad_idx, msg = verify_audit_log(log_file)
    assert is_valid is False
    assert bad_idx == 2
    assert "Tampering detected" in msg


def test_audit_log_broken_chain_detection(tmp_path):
    log_file = str(tmp_path / "broken_chain_audit.jsonl")
    audit = HashChainedAuditLog(log_file, config_hash="config_chain")
    
    for i in range(4):
        audit.log_decision(
            sample_id=i,
            score=1.0 * i,
            reasons=[],
            decision="keep",
            sample_weight=1.0,
        )
        
    # Delete entry index 1
    with open(log_file, "r") as f:
        entries = [json.loads(line) for line in f]
        
    entries_missing = [entries[0], entries[2], entries[3]]
    with open(log_file, "w") as f:
        for e in entries_missing:
            f.write(json.dumps(e) + "\n")
            
    # Verification must detect broken hash chain on entry 2
    is_valid, bad_idx, msg = verify_audit_log(log_file)
    assert is_valid is False
    assert bad_idx == 2
    assert "Broken hash chain" in msg
