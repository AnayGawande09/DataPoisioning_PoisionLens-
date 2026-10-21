"""Cryptographically hash-chained audit logging for PoisonLens quarantine decisions."""

from typing import Dict, Any, List, Tuple, Optional
import os
import json
import time
import hashlib
from datetime import datetime


GENESIS_HASH = "0" * 64


def canonical_json(data: Dict[str, Any]) -> str:
    """Serialize dictionary to deterministic, sorted JSON string for hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def compute_sha256(content: str) -> str:
    """Compute SHA-256 hex digest of string content."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class HashChainedAuditLog:
    """Tamper-evident audit log where each entry cryptographically hashes the previous entry."""

    def __init__(self, log_path: str, config_hash: str):
        self.log_path = log_path
        self.config_hash = config_hash
        self.current_index = 0
        self.last_hash = GENESIS_HASH
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
        
        # If log already exists, resume from the last entry
        if os.path.exists(log_path) and os.path.getsize(log_path) > 0:
            with open(log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
                if lines:
                    last_entry = json.loads(lines[-1].strip())
                    self.current_index = last_entry["index"] + 1
                    self.last_hash = last_entry["entry_hash"]

    def log_decision(
        self,
        sample_id: int,
        score: float,
        reasons: List[str],
        decision: str,
        sample_weight: float,
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Append a decision record to the hash-chained audit log."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        
        entry_payload = {
            "index": self.current_index,
            "timestamp": timestamp,
            "previous_hash": self.last_hash,
            "config_hash": self.config_hash,
            "sample_id": int(sample_id),
            "score": float(score),
            "reasons": reasons,
            "decision": str(decision),
            "sample_weight": float(sample_weight),
        }
        if extra_metadata:
            entry_payload["metadata"] = extra_metadata
            
        # Compute entry hash over canonical JSON of payload
        entry_hash = compute_sha256(canonical_json(entry_payload))
        full_entry = dict(entry_payload)
        full_entry["entry_hash"] = entry_hash
        
        # Append to log file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(full_entry) + "\n")
            
        # Update chain state
        self.last_hash = entry_hash
        self.current_index += 1
        
        return full_entry


def verify_audit_log(log_path: str) -> Tuple[bool, Optional[int], str]:
    """Verify cryptographic integrity of a hash-chained audit log.
    
    Checks:
    1. Each entry's entry_hash matches its recalculated content hash.
    2. Each entry's previous_hash matches the previous entry's entry_hash (genesis check on first).
    
    Returns:
        Tuple of (is_valid, corrupted_entry_index, status_message).
    """
    if not os.path.exists(log_path):
        return False, None, f"Audit log file not found: {log_path}"
        
    expected_prev_hash = GENESIS_HASH
    
    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
                
            try:
                entry = json.loads(line_str)
            except Exception as e:
                return False, line_num - 1, f"Line {line_num}: Malformed JSON - {e}"
                
            entry_index = entry.get("index")
            recorded_hash = entry.get("entry_hash")
            recorded_prev = entry.get("previous_hash")
            
            # Check previous hash link
            if recorded_prev != expected_prev_hash:
                return (
                    False,
                    entry_index,
                    f"Entry {entry_index} (line {line_num}): Broken hash chain! "
                    f"Expected previous_hash {expected_prev_hash[:16]}..., but found {recorded_prev[:16]}...",
                )
                
            # Recompute content hash
            payload = {k: v for k, v in entry.items() if k != "entry_hash"}
            recomputed_hash = compute_sha256(canonical_json(payload))
            
            if recomputed_hash != recorded_hash:
                return (
                    False,
                    entry_index,
                    f"Entry {entry_index} (line {line_num}): Tampering detected! "
                    f"Content recomputed hash {recomputed_hash[:16]}... != recorded {recorded_hash[:16]}...",
                )
                
            expected_prev_hash = recorded_hash
            
    return True, None, "Audit log verification SUCCESSFUL: All hash-chain links intact."
