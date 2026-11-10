from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import PurePosixPath
import tarfile
from tempfile import SpooledTemporaryFile

from ....config import ArtifactLimits


@dataclass(frozen=True)
class ArchiveMember:
    """A visible first-level file from a csmock result archive."""

    path: str
    name: str
    size: int


class ArchiveLimitError(ValueError):
    pass


def _parts(path: str) -> tuple[str, ...] | None:
    path = path.replace("\\", "/")
    if path.startswith("/"):
        return None
    parts = tuple(part for part in PurePosixPath(path).parts if part not in {".", ""})
    if not parts or ".." in parts:
        return None
    return parts


def _visible_member(member: tarfile.TarInfo) -> ArchiveMember | None:
    if not member.isfile():
        return None
    parts = _parts(member.name)
    if parts is None:
        return None

    # csmock archives normally contain NVR/<file>. Only expose files directly
    # below that directory and deliberately omit NVR/debug/.... Supporting a
    # flat archive keeps the reader tolerant of custom Jenkins steps.
    if len(parts) == 1:
        display_name = parts[0]
    else:
        if len(parts) != 2 or parts[1] == "debug":
            return None
        display_name = parts[1]
    return ArchiveMember(path="/".join(parts), name=display_name, size=member.size)


_REQUIRED_SCAN_FILES = frozenset({
    "scan.ini", "scan-results-summary.txt", "scan-results.js", "scan-results.err",
    "scan-results.html", "scan.log",
})


class CsmockArchive:
    """Validate one tar stream and serve visible files from a bounded spool.

    Keeping a seekable compressed TarFile open is not enough: reading members
    out of order can decompress the stream again. Cache only visible payloads,
    spilling beyond 1 MiB to a temporary file, and close it with the operation.
    """

    def __init__(self, content: bytes, limits: ArtifactLimits | None = None) -> None:
        limits = limits or ArtifactLimits()
        if len(content) > limits.max_archive_bytes:
            raise ArchiveLimitError("archive exceeds the configured size limit")
        self._cache = SpooledTemporaryFile(max_size=1024 * 1024, mode="w+b")
        self._offsets: dict[str, tuple[int, int]] = {}
        try:
            self.members = self._index(content, limits)
            required = [member for member in self.members if member.name in _REQUIRED_SCAN_FILES]
            self.has_scan_results = (
                len(required) == len(_REQUIRED_SCAN_FILES)
                and {member.name for member in required} == _REQUIRED_SCAN_FILES
                and len({member.path.rpartition("/")[0] for member in required}) == 1
            )
        except BaseException:
            self.close()
            raise

    def _index(self, content: bytes, limits: ArtifactLimits) -> tuple[ArchiveMember, ...]:
        visible: list[ArchiveMember] = []
        count = regular_file_bytes = 0
        with tarfile.open(fileobj=io.BytesIO(content), mode="r|*") as archive:
            for member in archive:
                count += 1
                if count > limits.max_archive_members:
                    raise ArchiveLimitError("archive has too many members")
                if not member.isfile():
                    continue
                if member.size < 0:
                    raise tarfile.ReadError("negative archive member size")
                if member.size > limits.max_archive_member_bytes:
                    raise ArchiveLimitError("archive member is too large")
                regular_file_bytes += member.size
                if regular_file_bytes > limits.max_archive_uncompressed_bytes:
                    raise ArchiveLimitError("archive expands beyond the configured limit")
                if content and regular_file_bytes / len(content) > limits.max_archive_compression_ratio:
                    raise ArchiveLimitError("archive compression ratio exceeds the configured limit")
                item = _visible_member(member)
                if item is None:
                    continue
                visible.append(item)
                # Preserve the first entry on duplicate paths. Result acceptance
                # still rejects duplicate required files using the full index.
                if item.path in self._offsets:
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise tarfile.ReadError("archive member is unreadable")
                offset = self._cache.tell()
                remaining = member.size
                with extracted:
                    while remaining:
                        chunk = extracted.read(min(64 * 1024, remaining))
                        if not chunk:
                            raise tarfile.ReadError("unexpected end of archive member")
                        self._cache.write(chunk)
                        remaining -= len(chunk)
                self._offsets[item.path] = (offset, member.size)
        return tuple(sorted(visible, key=lambda item: (item.name, item.path)))

    def read(self, member_path: str) -> bytes:
        """Read a canonical visible path without creating archive-named files."""
        offset, size = self._offsets[member_path]
        self._cache.seek(offset)
        return self._cache.read(size)

    def close(self) -> None:
        self._cache.close()

    def __enter__(self) -> CsmockArchive:
        return self

    def __exit__(self, *_args) -> None:
        self.close()
