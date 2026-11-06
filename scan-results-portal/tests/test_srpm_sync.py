import json

from sqlalchemy import select

from conftest import (
    RPM_SCAN_KEY,
    FakeJenkinsClient,
    rpm_manifest,
    srpm_scan_artifacts,
)

from scanservice import resync as resync_module
from scanservice.modules.srpm.models import SrpmScanSummary, SrpmScanTask
from scanservice.modules.srpm.services.synchronization import (
    _sync_build,
    sync_registered_tasks,
)
from scanservice.modules.srpm.services.sync_results import set_manifest


SARIF_DOCUMENT = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "csdiff", "version": "3.5.4"}},
            "results": [
                {
                    "ruleId": "core.NullDereference",
                    "level": "warning",
                    "message": {"text": "possible null dereference"},
                },
                {
                    "ruleId": "core.NullDereference",
                    "level": "warning",
                    "message": {"text": "possible null dereference"},
                },
            ],
        }
    ],
}


def test_sync_build_uses_sarif_summary_fallback(session, settings):
    archive = "srpm-scan-artifacts/5/curl-8.4.0-9.ocs23.tar.xz"
    sarif = "srpm-scan-artifacts/5/csmock-results/curl.sarif"
    artifacts = [
        {"fileName": archive, "relativePath": archive, "size": 1024, "url": None},
        {"fileName": "curl.sarif", "relativePath": sarif, "size": 512, "url": None},
    ]
    client = FakeJenkinsClient(
        artifacts=artifacts,
        contents={
            archive: b"not a tar archive",
            sarif: json.dumps(SARIF_DOCUMENT).encode(),
        },
    )

    task = _sync_build(session, client, settings, 5, job="csmock-curl-test")
    session.commit()

    assert task.srpm_name == "curl-8.4.0-9.ocs23.src.rpm"
    assert task.version == "8.4.0"
    assert task.release == "9.ocs23"
    assert task.nvr == "curl-8.4.0-9.ocs23"
    assert task.scanner == "csdiff"
    assert task.total_findings == 2
    # The archive itself is unusable, so the task is not FINISHED even though
    # the SARIF gave us a summary.
    assert task.scan_result == "NOT_AVAILABLE"
    assert session.scalars(select(SrpmScanSummary)).one().count == 2


def test_sync_build_ignores_rpm_artifacts_in_combined_job(session, settings):
    srpm_artifacts, srpm_contents = srpm_scan_artifacts(build_number=8)
    rpm_manifest_path = (
        f"rpm-scan-artifacts/8/{RPM_SCAN_KEY}/scan-manifest.json"
    )
    rpm_log_path = f"rpm-scan-artifacts/8/{RPM_SCAN_KEY}/scan.log"
    rpm_manifest_content = json.dumps(rpm_manifest()).encode()
    artifacts = srpm_artifacts + [
        {
            "fileName": "scan-manifest.json",
            "relativePath": rpm_manifest_path,
            "size": len(rpm_manifest_content),
            "url": None,
        },
        {
            "fileName": "scan.log",
            "relativePath": rpm_log_path,
            "size": 4,
            "url": None,
        },
    ]
    client = FakeJenkinsClient(
        artifacts=artifacts,
        contents={
            **srpm_contents,
            rpm_manifest_path: rpm_manifest_content,
            rpm_log_path: b"rpm\n",
        },
    )

    task = _sync_build(session, client, settings, 8, job="scan-docker")
    session.commit()

    assert task.scan_result == "FINISHED"
    assert task.sync_status == "SYNCED"
    assert task.version == "8.4.0"
    assert task.release == "9.ocs23"
    assert task.nvr == "curl-8.4.0-9.ocs23"
    assert task.scanner == "csmock"
    assert task.scanner_version == "csmock-3.8.7-2.ocs23"
    archive_path = next(iter(srpm_contents))
    assert {row.relative_path for row in task.artifacts} == {
        archive_path,
        f"{archive_path}::scan.ini",
        f"{archive_path}::scan-results-summary.txt",
        f"{archive_path}::scan-results.js",
        f"{archive_path}::scan-results.err",
        f"{archive_path}::scan-results.html",
        f"{archive_path}::scan.log",
    }
    assert all(
        row.relative_path.startswith("srpm-scan-artifacts/")
        for row in task.artifacts
    )


def test_set_manifest_normalizes_nested_scanner_and_ignores_rpm(session):
    task = SrpmScanTask(
        jenkins_job_full_name="scan-docker",
        jenkins_build_number=9,
        scan_result="RUNNING",
        sync_status="PENDING",
    )
    set_manifest(
        task,
        {
            "scan_type": "srpm",
            "scanner": {"name": "csmock", "version": "3.8.7"},
            "enabled_plugins": ["clang", "gcc"],
        },
    )
    assert task.scanner == "csmock"
    assert task.scanner_version == "3.8.7"
    assert task.enabled_plugins == ["clang", "gcc"]

    rpm_task = SrpmScanTask(
        jenkins_job_full_name="scan-docker",
        jenkins_build_number=10,
        scan_result="RUNNING",
        sync_status="PENDING",
    )
    set_manifest(rpm_task, rpm_manifest())
    assert rpm_task.scanner is None
    assert rpm_task.version is None
    assert rpm_task.scan_metadata is None


def test_sync_build_separates_jobs_with_same_build_number(session, settings):
    client = FakeJenkinsClient()

    _sync_build(session, client, settings, 5, job="packages/curl")
    _sync_build(session, client, settings, 5, job="packages/openssl")
    session.commit()

    tasks = session.scalars(
        select(SrpmScanTask).order_by(SrpmScanTask.jenkins_job_full_name)
    ).all()
    assert [task.jenkins_job_full_name for task in tasks] == [
        "packages/curl",
        "packages/openssl",
    ]


def test_sync_registered_tasks_only_resyncs_unfinished_tasks(
    session, settings, monkeypatch
):
    for build_number, scan_result in (
        (1, "FINISHED"),
        (2, "RUNNING"),
        (3, "NOT_AVAILABLE"),
        (4, "FAILED"),
    ):
        session.add(
            SrpmScanTask(
                jenkins_job_full_name="csmock-curl-test",
                jenkins_build_number=build_number,
                scan_result=scan_result,
                sync_status="PENDING",
            )
        )
    session.commit()

    client = FakeJenkinsClient()
    monkeypatch.setattr(resync_module, "JenkinsClient", lambda *args, **kwargs: client)

    result = sync_registered_tasks(settings, session)

    assert result == {"attempted": 2, "synced": 0, "pending": 0, "failed": 2}
    assert sorted(number for _, number in client.requested_builds) == [2, 3]
    assert client.closed is True
