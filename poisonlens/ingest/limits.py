"""Resource-limit enforcement for ingestion. All values come from ``ScanConfig.limits``."""

from __future__ import annotations

import os
from pathlib import Path

from poisonlens.core.config import ArchiveLimits, UploadLimits
from poisonlens.core.errors import LimitExceededError


def check_upload_size(size: int, limits: UploadLimits) -> None:
    if size <= 0:
        raise LimitExceededError("upload is empty", limit="min_upload_bytes", limit_value=1, observed=size)
    if size > limits.max_upload_bytes:
        raise LimitExceededError(
            f"upload of {size} bytes exceeds the {limits.max_upload_bytes}-byte limit",
            limit="max_upload_bytes",
            limit_value=limits.max_upload_bytes,
            observed=size,
        )


def directory_usage(root: Path) -> int:
    """Total size of regular files under ``root`` (does not follow symlinks)."""
    total = 0
    if not root.exists():
        return 0
    for dirpath, _dirs, files in os.walk(root, followlinks=False):
        for name in files:
            try:
                st = os.lstat(os.path.join(dirpath, name))
            except OSError:
                continue
            total += st.st_size
    return total


def check_disk_quota(data_dir: Path, incoming: int, limits: UploadLimits) -> None:
    used = directory_usage(data_dir)
    if used + incoming > limits.disk_quota_bytes:
        raise LimitExceededError(
            f"disk quota exceeded: {used} used + {incoming} incoming > {limits.disk_quota_bytes}",
            limit="disk_quota_bytes",
            limit_value=limits.disk_quota_bytes,
            observed=used + incoming,
        )


class ArchiveBudget:
    """Counts entries and decompressed bytes across one archive *and all archives nested in it*.

    Byte checks are applied while streaming, so declared sizes in headers cannot be
    used to lie past a cap.
    """

    def __init__(self, limits: ArchiveLimits, container_bytes: int):
        self.limits = limits
        self.container_bytes = max(1, container_bytes)
        self.entries = 0
        self.total_bytes = 0

    def add_entry(self) -> None:
        self.entries += 1
        if self.entries > self.limits.max_entries:
            raise LimitExceededError(
                f"archive has more than {self.limits.max_entries} entries",
                limit="max_entries",
                limit_value=self.limits.max_entries,
                observed=self.entries,
            )

    def check_declared(self, declared_size: int, compressed_size: int | None) -> None:
        """Reject on header values before reading anything (cheap early exit for honest bombs)."""
        self._check_member(declared_size, compressed_size)
        if self.total_bytes + declared_size > self.limits.max_total_bytes:
            raise LimitExceededError(
                "declared total uncompressed size exceeds the limit",
                limit="max_total_bytes",
                limit_value=self.limits.max_total_bytes,
                observed=self.total_bytes + declared_size,
            )

    def add_bytes(self, n: int, member_bytes: int, compressed_size: int | None) -> None:
        """Account for ``n`` new bytes of a member that has produced ``member_bytes`` so far."""
        self.total_bytes += n
        self._check_member(member_bytes, compressed_size)
        if self.total_bytes > self.limits.max_total_bytes:
            raise LimitExceededError(
                f"total uncompressed size exceeds {self.limits.max_total_bytes} bytes",
                limit="max_total_bytes",
                limit_value=self.limits.max_total_bytes,
                observed=self.total_bytes,
            )
        if (
            self.total_bytes >= self.limits.ratio_check_min_bytes
            and self.total_bytes / self.container_bytes > self.limits.max_compression_ratio
        ):
            raise LimitExceededError(
                "overall compression ratio exceeds the limit",
                limit="max_compression_ratio",
                limit_value=self.limits.max_compression_ratio,
                observed=round(self.total_bytes / self.container_bytes, 1),
            )

    def _check_member(self, member_bytes: int, compressed_size: int | None) -> None:
        if member_bytes > self.limits.max_entry_bytes:
            raise LimitExceededError(
                f"archive member exceeds {self.limits.max_entry_bytes} bytes",
                limit="max_entry_bytes",
                limit_value=self.limits.max_entry_bytes,
                observed=member_bytes,
            )
        if (
            compressed_size is not None
            and member_bytes >= self.limits.ratio_check_min_bytes
            and member_bytes / max(1, compressed_size) > self.limits.max_compression_ratio
        ):
            raise LimitExceededError(
                "member compression ratio exceeds the limit",
                limit="max_compression_ratio",
                limit_value=self.limits.max_compression_ratio,
                observed=round(member_bytes / max(1, compressed_size), 1),
            )
