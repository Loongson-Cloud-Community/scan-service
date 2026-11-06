from dataclasses import replace
import json

import pytest

from conftest import (
    FakeJenkinsClient,
    SRPM_SCAN_FILES,
    SRPM_SCAN_INI,
    SRPM_SUMMARY,
    srpm_scan_artifacts,
)
from scanservice.modules.srpm.models import SrpmScanTask
from scanservice.modules.srpm.services.synchronization import sync_build


def scan_members(**overrides):
    members = {name: "" for name in SRPM_SCAN_FILES}
    members.update({"scan.ini": SRPM_SCAN_INI, "scan-results-summary.txt": SRPM_SUMMARY})
    members.update(overrides)
    return members


def synchronize(session, settings, members, *, reported_exit_code=None):
    artifacts, contents = srpm_scan_artifacts(members=members)
    if reported_exit_code is not None:
        session.add(SrpmScanTask(
            jenkins_job_full_name="packages/curl", jenkins_build_number=6,
            scan_result="RUNNING", csmock_exit_code=reported_exit_code,
        ))
        session.flush()
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    return sync_build(session, client, settings, 6, job_full_name="packages/curl")


@pytest.mark.parametrize("ini", [
    "[unrelated]\nx=y\n",
    SRPM_SCAN_INI.replace("tool = csmock", "tool = unrelated"),
    SRPM_SCAN_INI.replace("[scan]", "[unrelated]"),
    SRPM_SCAN_INI.replace("exit-code = 0", "exit-code = invalid"),
    SRPM_SCAN_INI.replace("exit-code = 0", ""),
])
def test_invalid_metadata_is_not_a_finished_clean_scan(session, settings, ini):
    task = synchronize(session, settings, scan_members(**{"scan.ini": ini}))
    assert task.scan_result == "NOT_AVAILABLE"
    assert task.total_findings is None
    assert task.sync_status == "ERROR"
    assert task.sync_error


@pytest.mark.parametrize("summary", [
    "NOT A SUMMARY", SRPM_SUMMARY + "corrupt line\n", "-1 CLANG_WARNING problem",
    "CLANG_WARNING: problem -1", "\x00",
])
def test_invalid_summary_is_not_a_finished_clean_scan(session, settings, summary):
    task = synchronize(session, settings, scan_members(**{"scan-results-summary.txt": summary}))
    assert task.scan_result == "NOT_AVAILABLE"
    assert task.total_findings is None
    assert task.sync_error


@pytest.mark.parametrize("summary", ["", "\n  \n", "# no findings\n"])
def test_successful_scan_accepts_empty_summary(session, settings, summary):
    task = synchronize(session, settings, scan_members(**{"scan-results-summary.txt": summary}))
    assert task.scan_result == "FINISHED"
    assert task.total_findings == 0
    assert task.csmock_exit_code == 0
    assert task.sync_status == "SYNCED"
    assert task.sync_error is None


@pytest.mark.parametrize("ini_code,reported_code", [(1, None), (0, 2), (1, 0)])
def test_nonzero_scan_exit_code_cannot_be_finished(session, settings, ini_code, reported_code):
    task = synchronize(session, settings, scan_members(**{
        "scan.ini": SRPM_SCAN_INI.replace("exit-code = 0", f"exit-code = {ini_code}"),
    }), reported_exit_code=reported_code)
    assert task.scan_result == "FAILED"
    assert task.csmock_exit_code != 0


def test_reported_success_can_supply_missing_ini_exit_code(session, settings):
    task = synchronize(session, settings, scan_members(**{
        "scan.ini": SRPM_SCAN_INI.replace("exit-code = 0", ""),
    }), reported_exit_code=0)
    assert task.scan_result == "FINISHED"


@pytest.mark.parametrize("manifest", [[], None, "string", 7, "invalid-json"])
def test_invalid_optional_manifest_does_not_reject_valid_result(session, settings, manifest):
    content = "{" if manifest == "invalid-json" else json.dumps(manifest)
    task = synchronize(session, settings, scan_members(**{"scan-manifest.json": content}))
    assert task.scan_result == "FINISHED"
    assert task.total_findings == 13
    assert task.scan_metadata.get("manifest_error")


def test_required_files_from_different_roots_are_not_one_result(session, settings):
    members = {f"curl/{name}": content for name, content in scan_members().items()}
    members["other/scan-results-summary.txt"] = members.pop("curl/scan-results-summary.txt")
    task = synchronize(session, settings, members)
    assert task.scan_result == "NOT_AVAILABLE"
    assert task.total_findings is None


def test_duplicate_required_members_are_ambiguous(session, settings):
    members = {f"curl/{name}": content for name, content in scan_members().items()}
    members["other/scan.ini"] = SRPM_SCAN_INI
    task = synchronize(session, settings, members)
    assert task.scan_result == "NOT_AVAILABLE"
    assert task.total_findings is None


def test_single_nvr_root_is_accepted(session, settings):
    members = {f"curl/{name}": content for name, content in scan_members().items()}
    task = synchronize(session, settings, members)
    assert task.scan_result == "FINISHED"
    assert task.total_findings == 13


def test_optional_manifest_cannot_erase_reported_failure(session, settings):
    task = synchronize(session, settings, scan_members(**{
        "scan-manifest.json": json.dumps({"scan_type": "srpm", "csmock_exit_code": 0}),
    }), reported_exit_code=2)
    assert task.scan_result == "FAILED"
    assert task.csmock_exit_code == 2


def test_nonzero_reported_exit_code_without_archive_is_failed(session, settings):
    session.add(SrpmScanTask(
        jenkins_job_full_name="packages/curl", jenkins_build_number=6,
        scan_result="RUNNING", csmock_exit_code=2,
    ))
    session.flush()
    task = sync_build(session, FakeJenkinsClient(), settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "FAILED"


def test_oversized_required_file_cannot_be_replaced_by_direct_artifact(session, settings):
    # The archive is readable, but its summary exceeds the parsing budget.
    # A different, short direct summary must not make that archive valid.
    limit = 1024
    settings = replace(settings, artifact_limits=replace(settings.artifact_limits, max_parse_bytes=limit))
    artifacts, contents = srpm_scan_artifacts(members=scan_members(**{
        "scan-results-summary.txt": "x" * (limit + 1),
    }))
    path = "srpm-scan-artifacts/6/scan-results-summary.txt"
    artifacts.append({"fileName": "scan-results-summary.txt", "relativePath": path, "size": 0})
    contents[path] = b""
    task = sync_build(session, FakeJenkinsClient(artifacts=artifacts, contents=contents),
                      settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "NOT_AVAILABLE"
    assert task.total_findings is None
