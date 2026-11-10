import io
import tarfile
from tempfile import SpooledTemporaryFile
from unittest.mock import patch

import pytest

from scanservice.config import ArtifactLimits
from scanservice.modules.srpm.csmock import archive as archive_module
from scanservice.modules.srpm.csmock.archive import CsmockArchive


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

    with CsmockArchive(content) as archive:
        assert [(item.name, item.path) for item in archive.members] == [
            ("scan.ini", "curl-1/scan.ini"),
            ("scan.log", "curl-1/scan.log"),
        ]
        assert archive.read("curl-1/scan.ini").startswith(b"[scan]")
        with pytest.raises(KeyError):
            archive.read("curl-1/debug/details.txt")


def test_scan_archive_rejects_too_many_members():
    content = _archive()
    limits = ArtifactLimits(max_archive_members=1)

    with pytest.raises(ValueError, match="too many members"):
        with CsmockArchive(content, limits):
            pass


def test_scan_archive_rejects_large_member():
    content = _archive()
    limits = ArtifactLimits(max_archive_member_bytes=4)

    with pytest.raises(ValueError, match="member is too large"):
        with CsmockArchive(content, limits):
            pass


def test_scan_archive_rejects_excessive_expansion():
    content = _archive()
    limits = ArtifactLimits(max_archive_uncompressed_bytes=8)

    with pytest.raises(ValueError, match="expands beyond"):
        with CsmockArchive(content, limits):
            pass


def test_scan_archive_rejects_oversized_compressed_input():
    content = _archive()
    limits = ArtifactLimits(max_archive_bytes=len(content) - 1)

    with pytest.raises(ValueError, match="archive exceeds"):
        with CsmockArchive(content, limits):
            pass


def test_scan_archive_rejects_excessive_compression_ratio():
    limits = ArtifactLimits(max_archive_compression_ratio=10)

    with pytest.raises(ValueError, match="compression ratio"):
        with CsmockArchive(_highly_compressed_archive(), limits):
            pass


@pytest.fixture
def spools(monkeypatch, tmp_path):
    resources = []

    def create(*args, **kwargs):
        resource = SpooledTemporaryFile(*args, **kwargs, dir=tmp_path)
        resources.append(resource)
        return resource

    monkeypatch.setattr(archive_module, "SpooledTemporaryFile", create)
    return resources


def test_out_of_order_reads_reuse_the_index_without_reopening_archive(spools):
    content = _archive()
    with patch.object(tarfile, "open", wraps=tarfile.open) as opened:
        with CsmockArchive(content) as archive:
            assert archive.read("curl-1/scan.log") == b"scan complete\n"
            assert archive.read("curl-1/scan.ini") == b"[scan]\ntool=csmock\n"
            assert archive.read("curl-1/scan.log") == b"scan complete\n"
            assert opened.call_count == 1
            assert opened.call_args.kwargs["mode"] == "r|*"
            assert not spools[0].closed
    assert spools[0].closed
    with pytest.raises(ValueError, match="closed"):
        archive.read("curl-1/scan.log")


@pytest.mark.parametrize("failure", ["limit", "format", "truncated"])
def test_construction_errors_close_temporary_storage(spools, failure):
    if failure == "limit":
        content, limits = _archive(), ArtifactLimits(max_archive_members=1)
    elif failure == "format":
        content, limits = b"not a tar archive", ArtifactLimits()
    else:
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w:") as archive:
            member = tarfile.TarInfo("scan.log")
            member.size = 4096
            archive.addfile(member, io.BytesIO(b"x" * 4096))
        content, limits = output.getvalue()[:600], ArtifactLimits()
    with pytest.raises((ValueError, tarfile.TarError)):
        CsmockArchive(content, limits)
    assert len(spools) == 1
    assert spools[0].closed


def test_consumer_failure_closes_temporary_storage(spools):
    with pytest.raises(RuntimeError, match="consumer failed"):
        with CsmockArchive(_archive()):
            raise RuntimeError("consumer failed")
    assert spools[0].closed


def test_large_visible_file_spills_to_temporary_file(monkeypatch, tmp_path):
    resources = []

    class TrackedSpool(SpooledTemporaryFile):
        rollovers = 0

        def rollover(self):
            self.rollovers += 1
            return super().rollover()

    def create(*args, **kwargs):
        resource = TrackedSpool(*args, **kwargs, dir=tmp_path)
        resources.append(resource)
        return resource

    monkeypatch.setattr(archive_module, "SpooledTemporaryFile", create)
    payload = b"x" * (1024 * 1024 + 1)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        member = tarfile.TarInfo("scan.log")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))
    with CsmockArchive(output.getvalue()) as archive:
        assert resources[0].rollovers == 1
        assert archive.read("scan.log") == payload
    assert resources[0].closed


@pytest.mark.parametrize("path", ["../scan.ini", "/scan.ini", "curl-1/debug/file", "./curl-1/scan.ini"])
def test_reader_rejects_unindexed_or_noncanonical_paths(path):
    with CsmockArchive(_archive()) as archive:
        with pytest.raises(KeyError):
            archive.read(path)


def test_hidden_files_still_count_towards_expansion_limits():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        member = tarfile.TarInfo("curl-1/debug/hidden")
        member.size = 1024
        archive.addfile(member, io.BytesIO(b"x" * 1024))
    with pytest.raises(ValueError, match="expands beyond"):
        CsmockArchive(output.getvalue(), ArtifactLimits(max_archive_uncompressed_bytes=100))


def test_unsafe_paths_and_links_are_not_cached_or_exposed():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        for name in ("/scan.ini", "../scan.log", "curl-1/../../scan.log"):
            member = tarfile.TarInfo(name)
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            member = tarfile.TarInfo("curl-1/link")
            member.type, member.linkname = kind, "/etc/passwd"
            archive.addfile(member)
    with CsmockArchive(output.getvalue()) as archive:
        assert archive.members == ()
        assert not archive.has_scan_results
