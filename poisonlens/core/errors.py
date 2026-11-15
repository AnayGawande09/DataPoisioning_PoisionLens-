"""Typed exceptions shared by every stage.

Stages raise these instead of bare ``Exception`` so the orchestrator and API can
map them to findings, HTTP status codes and partial reports consistently.
"""

from __future__ import annotations

from typing import Any


class PoisonLensError(Exception):
    """Base class for all PoisonLens errors."""


class ConfigError(PoisonLensError):
    """A scan configuration file or override is invalid (unknown key, bad value, bad YAML)."""


class UnsafeFileError(PoisonLensError):
    """An uploaded file (or archive member) must not be parsed further.

    ``check_id`` names the security check that decided this (e.g. ``"F03"``, ``"F07"``).
    """

    def __init__(self, message: str, *, check_id: str | None = None, location: str | None = None):
        super().__init__(message)
        self.check_id = check_id
        self.location = location


class UnsupportedFormatError(PoisonLensError):
    """No adapter can read the file, or the format is rejected by policy (e.g. SVG, executables)."""

    def __init__(self, message: str, *, detected_kind: str | None = None):
        super().__init__(message)
        self.detected_kind = detected_kind


class LimitExceededError(PoisonLensError):
    """A configured resource limit was hit (size, entry count, ratio, depth, memory, time)."""

    def __init__(self, message: str, *, limit: str, limit_value: Any = None, observed: Any = None):
        super().__init__(message)
        self.limit = limit
        self.limit_value = limit_value
        self.observed = observed


class PathSafetyError(PoisonLensError, ValueError):
    """An identifier or relative path would escape its sandbox (traversal, absolute path, bad id)."""
