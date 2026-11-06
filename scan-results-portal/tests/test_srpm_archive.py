import io
import tarfile

import pytest

from scanservice.config import ArtifactLimits
from scanservice.modules.srpm.csmock.archive import (
    list_visible_members,
    read_visible_member,
)


def _archive() -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:xz") as archive:
        for name, content in (
            ("curl-1/scan.ini", b"[scan]\ntool=csmock\n"),
            ("curl-1/scan.log", b"scan complete\n"),
            ("curl-1/debug/details.txt", b"internal\n"),
            ("curl-1/nested/ignored.txt", b"ignored\n"),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _highly_compressed_archive() -> bytes:
    output = io.BytesIO()
    content = b"0" * (1024 * 1024)
    with tarfile.open(fileobj=output, mode="w:xz") as archive:
        info = tarfile.TarInfo("curl-1/scan.log")
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def test_scan_archive_exposes_only_first_level_non_debug_files():
    content = _archive()

    members = list_visible_members(content)

    assert [(item.name, item.path) for item in members] == [
        ("scan.ini", "curl-1/scan.ini"),
        ("scan.log", "curl-1/scan.log"),
    ]
    assert read_visible_member(content, "curl-1/scan.ini").startswith(b"[scan]")
    with pytest.raises(KeyError):
        read_visible_member(content, "curl-1/debug/details.txt")


def test_scan_archive_rejects_too_many_members():
    content = _archive()
    limits = ArtifactLimits(max_archive_members=1)

    with pytest.raises(ValueError, match="too many members"):
        list_visible_members(content, limits)


def test_scan_archive_rejects_large_member():
    content = _archive()
    limits = ArtifactLimits(max_archive_member_bytes=4)

    with pytest.raises(ValueError, match="member is too large"):
        list_visible_members(content, limits)


def test_scan_archive_rejects_excessive_expansion():
    content = _archive()
    limits = ArtifactLimits(max_archive_uncompressed_bytes=8)

    with pytest.raises(ValueError, match="expands beyond"):
        list_visible_members(content, limits)


def test_scan_archive_rejects_oversized_compressed_input():
    content = _archive()
    limits = ArtifactLimits(max_archive_bytes=len(content) - 1)

    with pytest.raises(ValueError, match="archive exceeds"):
        list_visible_members(content, limits)


def test_scan_archive_rejects_excessive_compression_ratio():
    limits = ArtifactLimits(max_archive_compression_ratio=10)

    with pytest.raises(ValueError, match="compression ratio"):
        list_visible_members(_highly_compressed_archive(), limits)
