"""Individually legal archives must still share one bounded sync workload."""

from dataclasses import replace
import io
import tarfile
from tempfile import SpooledTemporaryFile

import httpx
import pytest

from conftest import FakeJenkinsClient, SRPM_SCAN_INI, SRPM_SUMMARY, srpm_archive_bytes
from scanservice.config import ArtifactLimits, Settings
from scanservice.jenkins import JenkinsArtifactTooLarge, JenkinsClient
from scanservice.modules.srpm.csmock import archive as archive_module
from scanservice.modules.srpm.models import SrpmScanTask
from scanservice.modules.srpm.services.synchronization import sync_build


def complete_archive():
    return srpm_archive_bytes()


@pytest.fixture
def spools(monkeypatch):
    resources = []

    def create(*args, **kwargs):
        resource = SpooledTemporaryFile(*args, **kwargs)
        resources.append(resource)
        return resource

    monkeypatch.setattr(archive_module, "SpooledTemporaryFile", create)
    return resources


class StreamingJenkins(FakeJenkinsClient):
    """Expose chunked reads and record closure, including interrupted downloads."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.streams_closed = []
        self.allowances = []

    def iter_artifact(self, job, number, path, *, max_bytes, chunk_size=64 * 1024):
        self.requested_artifacts.append(path)
        self.allowances.append(max_bytes)
        try:
            total = 0
            for offset in range(0, len(self.contents[path]), 32):
                chunk = self.contents[path][offset:offset + 32]
                total += len(chunk)
                if total > max_bytes:
                    raise JenkinsArtifactTooLarge("stream limit")
                yield chunk
        finally:
            self.streams_closed.append(path)


def client_for(contents, *, building=False):
    paths = [f"srpm-scan-artifacts/6/{name}" for name in contents]
    return StreamingJenkins(
        building=building,
        artifacts=[{"fileName": path.rsplit("/", 1)[-1], "relativePath": path} for path in paths],
        contents=dict(zip(paths, contents.values())),
    )


@pytest.mark.parametrize("kind", ["bytes", "members", "expanded"])
def test_sync_rejects_combined_archive_workload_before_publishing_results(session, settings, spools, kind):
    content = complete_archive()
    caps = {
        "bytes": {"max_archive_bytes": len(content) * 2 - 1},
        "members": {"max_archive_members": 6},
        "expanded": {"max_archive_uncompressed_bytes": sum(map(len, (
            SRPM_SCAN_INI.encode(), SRPM_SUMMARY.encode(), b"/* js */\n", b"err\n",
            b"<html></html>\n", b"log\n",
        ))) * 2 - 1},
    }
    limits = replace(settings.artifact_limits, **caps[kind])
    settings = replace(settings, artifact_limits=limits)
    client = client_for({"curl-8.4.0-9.ocs23.tar.xz": content, "extra.tar.xz": content,
                         "never-read.tar.xz": content})
    if kind == "bytes":
        for row in client.artifacts:
            row["size"] = 0  # Reported sizes cannot replace actual byte accounting.
    task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "NOT_AVAILABLE"
    assert task.sync_status == "ERROR"
    assert "sync archive" in task.sync_error.lower()
    assert task.total_findings is None
    assert len(client.requested_artifacts) == 2
    assert client.streams_closed == client.requested_artifacts
    assert len(spools) == (1 if kind == "bytes" else 2)
    assert all(resource.closed for resource in spools)


def test_downloaded_corrupt_archives_still_consume_the_sync_budget(session, settings):
    content = b"x" * 200
    settings = replace(settings, artifact_limits=replace(settings.artifact_limits, max_archive_bytes=300))
    client = client_for({"bad.tar.xz": content, "another.tar.xz": content,
                         "never-read.tar.xz": complete_archive()})
    task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "NOT_AVAILABLE"
    assert "sync archive" in task.sync_error.lower()
    assert len(client.requested_artifacts) == 2
    assert client.streams_closed == client.requested_artifacts


def test_workload_at_all_three_limits_is_accepted(session, settings):
    content = complete_archive()
    expanded = sum(map(len, (SRPM_SCAN_INI.encode(), SRPM_SUMMARY.encode(), b"/* js */\n",
                             b"err\n", b"<html></html>\n", b"log\n")))
    settings = replace(settings, artifact_limits=replace(settings.artifact_limits,
        max_archive_bytes=len(content) * 2, max_archive_members=12,
        max_archive_uncompressed_bytes=expanded * 2, max_sync_archives=2))
    client = client_for({"curl-8.4.0-9.ocs23.tar.xz": content, "extra.tar.xz": content})
    task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "FINISHED"
    assert task.total_findings == 13
    assert client.streams_closed == client.requested_artifacts


@pytest.mark.parametrize("oversized", [False, True])
def test_bad_or_pre_rejected_archives_cannot_bypass_attempt_limit(session, settings, oversized):
    settings = replace(settings, artifact_limits=replace(settings.artifact_limits, max_sync_archives=2))
    client = client_for({f"bad-{i}.zip": b"" for i in range(5)})
    if oversized:
        for row in client.artifacts:
            row["size"] = settings.artifact_limits.max_archive_bytes + 1
    task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "NOT_AVAILABLE"
    assert "attempt limit" in task.sync_error
    assert len(client.requested_artifacts) == (0 if oversized else 2)


def test_headers_of_failed_archives_are_not_refunded(session, settings):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:") as archive:
        member = tarfile.TarInfo("curl/debug/hidden")
        member.size = 200
        archive.addfile(member, io.BytesIO(b"x" * 200))
    settings = replace(settings, artifact_limits=replace(settings.artifact_limits,
                        max_archive_uncompressed_bytes=300))
    client = client_for({"truncated.tar": output.getvalue()[:520],
                         "curl-8.4.0-9.ocs23.tar.xz": complete_archive(),
                         "never-read.tar.xz": complete_archive()})
    task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "NOT_AVAILABLE"
    assert "expansion budget" in task.sync_error
    assert len(client.requested_artifacts) == 2


def test_partial_io_failure_closes_stream_and_does_not_try_another_archive(session, settings):
    client = client_for({"failed.tar": b"", "never-read.tar.xz": complete_archive()})

    def interrupted(job, number, path, **kwargs):
        client.requested_artifacts.append(path)
        try:
            yield b"partial"
            raise OSError("connection lost")
        finally:
            client.streams_closed.append(path)

    client.iter_artifact = interrupted
    with pytest.raises(OSError, match="connection lost"):
        sync_build(session, client, settings, 6, job_full_name="packages/curl")
    assert len(client.requested_artifacts) == 1
    assert client.streams_closed == client.requested_artifacts


@pytest.mark.parametrize("reported_failure,building", [(False, False), (False, True), (True, True)])
def test_budget_error_preserves_known_scan_facts_and_closes_spools(
    session, settings, spools, reported_failure, building,
):
    settings = replace(settings, artifact_limits=replace(settings.artifact_limits, max_sync_archives=1))
    session.add(SrpmScanTask(jenkins_job_full_name="packages/curl", jenkins_build_number=6,
                            scan_result="RUNNING", csmock_exit_code=2 if reported_failure else None))
    session.flush()
    client = client_for({"curl-8.4.0-9.ocs23.tar.xz": complete_archive(),
                         "never-read.tar.xz": complete_archive()}, building=building)
    task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    assert task.scan_result == ("FAILED" if reported_failure else "RUNNING" if building else "NOT_AVAILABLE")
    assert task.sync_status == ("SYNCED" if reported_failure else "ERROR")
    assert task.total_findings is None
    assert len(spools) == 1
    assert all(resource.closed for resource in spools)
    assert len(client.requested_artifacts) == 1


def test_a_later_sync_gets_a_fresh_budget_and_can_recover(session, settings):
    content = complete_archive()
    settings = replace(settings, artifact_limits=replace(settings.artifact_limits, max_sync_archives=1))
    client = client_for({"curl-8.4.0-9.ocs23.tar.xz": content, "extra.tar.xz": content})
    task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "NOT_AVAILABLE"
    client.artifacts.pop()
    task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "FINISHED"
    assert task.sync_error is None
    assert task.total_findings == 13


@pytest.mark.parametrize("declared_length", [False, True])
def test_real_jenkins_stream_overflow_is_closed_before_processing_later_archives(session, settings, declared_length):
    content = complete_archive()
    closed, requested = [], []

    class Body(httpx.SyncByteStream):
        def __init__(self, path):
            self.path = path

        def __iter__(self):
            yield content

        def close(self):
            closed.append(self.path)

    paths = [f"srpm-scan-artifacts/6/{name}" for name in (
        "curl-8.4.0-9.ocs23.tar.xz", "extra.tar.xz", "never-read.tar.xz")]

    def handle(request):
        if request.url.path.endswith("/api/json"):
            return httpx.Response(200, json={"building": False, "artifacts": [
                {"relativePath": path, "fileName": path.rsplit("/", 1)[-1]} for path in paths]})
        path = request.url.path.split("/artifact/")[1]
        requested.append(path)
        headers = {"content-length": str(len(content))} if declared_length else {}
        return httpx.Response(200, stream=Body(path), headers=headers)

    settings = replace(settings, artifact_limits=replace(settings.artifact_limits,
                        max_archive_bytes=len(content) * 2 - 1))
    client = JenkinsClient("http://jenkins")
    client.client.close()
    client.client = httpx.Client(transport=httpx.MockTransport(handle))
    try:
        task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    finally:
        client.close()
    assert task.scan_result == "NOT_AVAILABLE"
    assert "download budget" in task.sync_error
    assert requested == closed == paths[:2]


def test_archive_attempt_limit_is_configurable_without_new_environment_variables(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text("artifacts:\n  max_sync_archives: 3\n", encoding="utf-8")
    monkeypatch.setenv("SCAN_SERVICE_CONFIG", str(config))
    assert Settings.from_environment().artifact_limits.max_sync_archives == 3
    with pytest.raises(ValueError, match="positive"):
        ArtifactLimits(max_sync_archives=0)
