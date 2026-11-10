"""Sync and artifact delivery must not repeatedly decompress the same archive."""

import json
from tempfile import SpooledTemporaryFile
from unittest.mock import patch

import pytest

from conftest import FakeJenkinsClient, SRPM_SCAN_FILES, SRPM_SCAN_INI, SRPM_SUMMARY, srpm_scan_artifacts
from scanservice.modules.srpm.csmock import archive as archive_module
from scanservice.modules.srpm.models import SrpmScanArtifact
from scanservice.modules.srpm.services import artifacts as artifacts_module
from scanservice.modules.srpm.services import synchronization
from scanservice.modules.srpm.services.artifacts import archive_member_response, artifact_response
from scanservice.modules.srpm.services.synchronization import sync_build


def scan_files():
    return {
        **{name: "" for name in SRPM_SCAN_FILES},
        "scan.ini": SRPM_SCAN_INI,
        "scan-results-summary.txt": SRPM_SUMMARY,
        "scan-manifest.json": json.dumps({"scan_type": "srpm", "scanner": "csmock"}),
        "scan.sarif": json.dumps({"runs": [{
            "tool": {"driver": {"name": "csmock"}},
            "results": [{"message": {"text": "one finding"}, "ruleId": "test-rule"}],
        }]}),
    }


def test_sync_opens_each_archive_once_for_all_result_files(session, settings):
    artifacts, contents = srpm_scan_artifacts(members=scan_files())
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    with patch.object(archive_module.tarfile, "open", wraps=archive_module.tarfile.open) as opened:
        task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "FINISHED"
    assert task.total_findings == 1
    assert task.scan_metadata["manifest"]["scanner"] == "csmock"
    assert len(client.requested_artifacts) == 1
    assert opened.call_count == 1


@pytest.mark.parametrize("action", ["view", "download", "archive"])
def test_archive_member_delivery_opens_archive_once(session, settings, monkeypatch, action):
    artifacts, contents = srpm_scan_artifacts()
    task = sync_build(session, FakeJenkinsClient(artifacts=artifacts, contents=contents),
                      settings, 6, job_full_name="packages/curl")
    session.flush()
    session.expire(task, ["artifacts"])
    row = next(row for row in task.artifacts if row.name == "scan.log")
    assert isinstance(row, SrpmScanArtifact)
    client = FakeJenkinsClient(contents=contents)
    monkeypatch.setattr(artifacts_module, "JenkinsClient", lambda *args: client)
    monkeypatch.setattr(artifacts_module, "get_settings", lambda: settings)
    with patch.object(archive_module.tarfile, "open", wraps=archive_module.tarfile.open) as opened:
        response = (archive_member_response(task, row.relative_path) if action == "archive"
                    else artifact_response(task, row, download=action == "download"))
    assert response.status_code == 200
    assert response.body == b"log\n"
    assert client.closed
    assert len(client.requested_artifacts) == 1
    assert opened.call_count == 1


@pytest.mark.parametrize("fail", [False, True])
def test_sync_releases_all_readers_even_if_parsing_fails(session, settings, monkeypatch, fail):
    artifacts, contents = srpm_scan_artifacts(members=scan_files())
    extra_path = "srpm-scan-artifacts/6/extra.tgz"
    artifacts.append({"fileName": "extra.tgz", "relativePath": extra_path})
    contents[extra_path] = contents[artifacts[0]["relativePath"]]
    resources = []

    def create(*args, **kwargs):
        resource = SpooledTemporaryFile(*args, **kwargs)
        resources.append(resource)
        return resource

    monkeypatch.setattr(archive_module, "SpooledTemporaryFile", create)
    if fail:
        def parse_failure(*args):
            raise RuntimeError("parser failed")
        monkeypatch.setattr(synchronization, "parse_summary", parse_failure)
    with patch.object(archive_module.tarfile, "open", wraps=archive_module.tarfile.open) as opened:
        if fail:
            with pytest.raises(RuntimeError, match="parser failed"):
                sync_build(session, FakeJenkinsClient(artifacts=artifacts, contents=contents),
                           settings, 6, job_full_name="packages/curl")
        else:
            task = sync_build(session, FakeJenkinsClient(artifacts=artifacts, contents=contents),
                              settings, 6, job_full_name="packages/curl")
            assert task.scan_result == "FINISHED"
    assert opened.call_count == len(resources) == 2
    assert all(resource.closed for resource in resources)
