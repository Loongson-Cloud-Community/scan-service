from __future__ import annotations

from dataclasses import dataclass
import io
from pathlib import PurePosixPath
import tarfile

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


def _validated_members(
    content: bytes, limits: ArtifactLimits
) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    regular_file_bytes = 0
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
        for member in archive:
            members.append(member)
            if len(members) > limits.max_archive_members:
                raise ArchiveLimitError("archive has too many members")
            if not member.isfile():
                continue
            if member.size > limits.max_archive_member_bytes:
                raise ArchiveLimitError("archive member is too large")
            regular_file_bytes += member.size
            if regular_file_bytes > limits.max_archive_uncompressed_bytes:
                raise ArchiveLimitError("archive expands beyond the configured limit")
            if content and (
                regular_file_bytes / len(content)
                > limits.max_archive_compression_ratio
            ):
                raise ArchiveLimitError(
                    "archive compression ratio exceeds the configured limit"
                )
    return members


def list_visible_members(
    content: bytes, limits: ArtifactLimits | None = None
) -> list[ArchiveMember]:
    limits = limits or ArtifactLimits()
    if len(content) > limits.max_archive_bytes:
        raise ArchiveLimitError("archive exceeds the configured size limit")
    visible: list[ArchiveMember] = []
    for member in _validated_members(content, limits):
        item = _visible_member(member)
        if item is not None:
            visible.append(item)
    return sorted(visible, key=lambda item: (item.name, item.path))


def read_visible_member(
    content: bytes,
    member_path: str,
    limits: ArtifactLimits | None = None,
) -> bytes:
    """Read one member after applying the same visibility/path checks."""
    limits = limits or ArtifactLimits()
    if len(content) > limits.max_archive_bytes:
        raise ArchiveLimitError("archive exceeds the configured size limit")
    requested = _parts(member_path)
    if requested is None:
        raise KeyError(member_path)
    normalized = "/".join(requested)
    members = _validated_members(content, limits)
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as archive:
        for member in members:
            item = _visible_member(member)
            if item is None or item.path != normalized:
                continue
            extracted = archive.extractfile(member)
            if extracted is None:
                break
            result = extracted.read(limits.max_archive_member_bytes + 1)
            if len(result) > limits.max_archive_member_bytes:
                raise ArchiveLimitError("archive member is too large")
            return result
    raise KeyError(member_path)
