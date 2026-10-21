"""Utility functions for PoisonLens: seeding, git-style data hashing, RNG persistence."""

import os
import json
import random
import hashlib
from typing import Sequence, Dict, Any, Tuple
import numpy as np
import torch


def set_seed(seed: int = 42) -> None:
    """Set seeds across Python, NumPy, and PyTorch for strict determinism."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    torch.backends.cudnn.deterministic = True
    torch.backends.cudnn.benchmark = False


def compute_git_hash(data_bytes: bytes) -> str:
    """Compute a git-style SHA-1 hash for a byte payload (blob <size>\\0<data>)."""
    header = f"blob {len(data_bytes)}\\0".encode("utf-8")
    return hashlib.sha1(header + data_bytes).hexdigest()


def compute_indices_hash(indices: Sequence[int]) -> str:
    """Compute a git-style SHA-1 hash for a list/array of sample indices."""
    indices_str = ",".join(str(idx) for idx in indices)
    return compute_git_hash(indices_str.encode("utf-8"))


def get_rng_states() -> Dict[str, Any]:
    """Capture full RNG states across Python, NumPy, and PyTorch."""
    states = {
        "python_rng": random.getstate(),
        "numpy_rng": np.random.get_state(),
        "torch_cpu_rng": torch.get_rng_state(),
    }
    if torch.cuda.is_available():
        states["torch_cuda_rng"] = torch.cuda.get_rng_state_all()
    return states


def set_rng_states(states: Dict[str, Any]) -> None:
    """Restore full RNG states across Python, NumPy, and PyTorch."""
    if "python_rng" in states:
        random.setstate(states["python_rng"])
    if "numpy_rng" in states:
        np.random.set_state(states["numpy_rng"])
    if "torch_cpu_rng" in states:
        torch.set_rng_state(states["torch_cpu_rng"])
    if torch.cuda.is_available() and "torch_cuda_rng" in states:
        torch.cuda.set_rng_state_all(states["torch_cuda_rng"])


def ensure_dir(path: str) -> str:
    """Ensure a directory exists and return the path."""
    os.makedirs(path, exist_ok=True)
    return path
