"""Cumulative archive work for one SRPM synchronization, never shared by tasks."""

from dataclasses import dataclass

from ....config import ArtifactLimits


class ArchiveLimitError(ValueError):
    pass


class ArchiveBudgetExceeded(ArchiveLimitError):
    """The whole synchronization must stop, not merely skip this archive."""


@dataclass
class ArchiveBudget:
    limits: ArtifactLimits
    archives: int = 0
    downloaded_bytes: int = 0
    members: int = 0
    expanded_bytes: int = 0

    @property
    def remaining_download_bytes(self) -> int:
        return max(0, self.limits.max_archive_bytes - self.downloaded_bytes)

    def start_archive(self) -> None:
        self.archives += 1
        if self.archives > self.limits.max_sync_archives:
            raise ArchiveBudgetExceeded("SRPM sync archive attempt limit exceeded")
        if not self.remaining_download_bytes:
            raise ArchiveBudgetExceeded("SRPM sync archive download budget exhausted")

    def download(self, size: int) -> None:
        self.downloaded_bytes += size
        if self.downloaded_bytes > self.limits.max_archive_bytes:
            raise ArchiveBudgetExceeded("SRPM sync archive download budget exhausted")

    def member(self) -> None:
        self.members += 1
        if self.members > self.limits.max_archive_members:
            raise ArchiveBudgetExceeded("SRPM sync archive member budget exhausted")

    def expand(self, size: int) -> None:
        # Reserve declared regular-file bytes before any extraction. Failed
        # archives do not refund work; hidden files and duplicates count too.
        self.expanded_bytes += size
        if self.expanded_bytes > self.limits.max_archive_uncompressed_bytes:
            raise ArchiveBudgetExceeded("SRPM sync archive expansion budget exhausted")
