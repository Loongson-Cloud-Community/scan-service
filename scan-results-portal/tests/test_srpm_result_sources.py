"""Optional archive data must belong to the selected csmock result root."""

import json

import pytest

from conftest import FakeJenkinsClient, SRPM_SCAN_FILES, SRPM_SCAN_INI, SRPM_SUMMARY, srpm_scan_artifacts
from scanservice.modules.srpm.csmock.archive import CsmockArchive
from scanservice.modules.srpm.services.synchronization import sync_build


def scan_files(root="curl"):
    return {f"{root}/{name}" if root else name: content for name, content in {
        **dict.fromkeys(SRPM_SCAN_FILES, ""),
        "scan.ini": SRPM_SCAN_INI,
        "scan-results-summary.txt": SRPM_SUMMARY,
    }.items()}


def sarif(count=1):
    return json.dumps({"runs": [{
        "tool": {"driver": {"name": "csmock"}},
        "results": [{"ruleId": f"issue-{i}", "message": {"text": "finding"}}
                    for i in range(count)],
    }]})


def synchronize(session, settings, members, extra_members=None):
    artifacts, contents = srpm_scan_artifacts(members=members)
    if extra_members is not None:
        extra_artifacts, extra_contents = srpm_scan_artifacts(nvr="extra", members=extra_members)
        artifacts += extra_artifacts
        contents.update(extra_contents)
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    task = sync_build(session, client, settings, 6, job_full_name="packages/curl")
    return task, client


@pytest.mark.parametrize("root", ["", "curl"])
def test_manifest_outside_selected_result_root_cannot_change_scan_outcome(session, settings, root):
    members = {**scan_files(root), "other/scan-manifest.json": json.dumps({
        "scan_type": "srpm", "scanner": "csmock", "csmock_exit_code": 2,
    })}
    task, _ = synchronize(session, settings, members)
    assert task.scan_result == "FINISHED"
    assert task.csmock_exit_code == 0
    assert task.total_findings == 13
    assert "manifest" not in task.scan_metadata


@pytest.mark.parametrize("root", ["", "curl"])
def test_sarif_outside_selected_result_root_cannot_replace_findings(session, settings, root):
    task, _ = synchronize(session, settings, {**scan_files(root), "other/scan.sarif": sarif()})
    assert task.scan_result == "FINISHED"
    assert task.total_findings == 13


@pytest.mark.parametrize("complete_extra", [False, True])
def test_sarif_from_another_archive_cannot_replace_selected_results(session, settings, complete_extra):
    extra = {**(scan_files() if complete_extra else {}), "curl/scan.sarif": sarif()}
    task, _ = synchronize(session, settings, scan_files(), extra)
    assert task.scan_result == "FINISHED"
    assert task.total_findings == 13


def test_only_selected_root_sarif_and_manifest_are_used(session, settings):
    members = {
        **scan_files(),
        "curl/scan.sarif": sarif(2),
        "curl/scan-manifest.json": json.dumps({"scan_type": "srpm", "scanner_version": "selected"}),
        "aaa/scan.sarif": sarif(3),
        "aaa/scan-manifest.json": json.dumps({"scan_type": "srpm", "scanner_version": "other"}),
    }
    task, client = synchronize(session, settings, members)
    assert task.scan_result == "FINISHED"
    assert task.total_findings == 2
    assert task.scanner_version == "selected"
    assert len(client.requested_artifacts) == 1


def test_standalone_optional_files_remain_supported(session, settings):
    artifacts, contents = srpm_scan_artifacts(members=scan_files())
    for name, content in {
        "scan.sarif": sarif(2),
        "scan-manifest.json": json.dumps({"scan_type": "srpm", "scanner_version": "standalone"}),
    }.items():
        path = f"srpm-scan-artifacts/6/{name}"
        artifacts.append({"fileName": name, "relativePath": path, "size": len(content.encode())})
        contents[path] = content.encode()
    task = sync_build(session, FakeJenkinsClient(artifacts=artifacts, contents=contents),
                      settings, 6, job_full_name="packages/curl")
    assert task.scan_result == "FINISHED"
    assert task.total_findings == 2
    assert task.scanner_version == "standalone"


def test_result_member_scope_does_not_hide_other_files_from_logs():
    artifacts, contents = srpm_scan_artifacts(members={**scan_files(), "other/notes.txt": "notes"})
    with CsmockArchive(contents[artifacts[0]["relativePath"]]) as archive:
        assert len(archive.result_members) == 6
        assert all(member.path.startswith("curl/") for member in archive.result_members)
        assert archive.read("other/notes.txt") == b"notes"
        assert len(archive.members) == 7


def test_incomplete_archive_has_no_complete_result_scope():
    artifacts, contents = srpm_scan_artifacts(members={"curl/scan.ini": SRPM_SCAN_INI})
    with CsmockArchive(contents[artifacts[0]["relativePath"]]) as archive:
        assert not archive.has_scan_results
        assert archive.result_members == ()
