import pytest
from sqlalchemy import select

from conftest import (
    RPM_BUILD_NUMBER,
    RPM_SCAN_KEY,
    FakeJenkinsClient,
    rpm_scan_artifacts,
)

from scanservice import resync as resync_module
from scanservice.modules.rpm.models import (
    RpmScanComponent,
    RpmScanTask,
    RpmScanVulnerability,
)
from scanservice.modules.rpm.services.synchronization import (
    sync_registered_tasks,
    sync_task,
)


def _task(
    session, *, build_number=RPM_BUILD_NUMBER, state="RUNNING", scan_key=RPM_SCAN_KEY
):
    task = RpmScanTask(
        scan_key=scan_key,
        jenkins_job_full_name="rpm-docker-test",
        jenkins_build_number=build_number,
        rpm_name="docker-24.0.9-8.lns23.loongarch64.rpm",
        rpm_sha256=scan_key,
        state=state,
        sync_status="PENDING",
    )
    session.add(task)
    session.commit()
    return task


def test_sync_task_finishes_when_results_are_valid(session):
    artifacts, contents = rpm_scan_artifacts(exit_code=0)
    client = FakeJenkinsClient(
        artifacts=artifacts,
        contents=contents,
        causes=({"userName": "wuhao"},),
    )
    task = _task(session)

    sync_task(session, client, task)
    session.commit()

    assert task.state == "FINISHED"
    assert task.sync_status == "SYNCED"
    assert task.sync_error is None
    assert task.triggered_by == "wuhao"
    # RPM metadata comes from the manifest, not from the file name.
    assert task.name == "docker"
    assert task.epoch == "8"
    assert task.version == "24.0.9"
    assert task.release == "8.lns23"
    assert task.architecture == "loongarch64"
    assert task.source_rpm == "docker-24.0.9-8.lns23.src.rpm"
    assert task.rpm_size_bytes == 16764070
    assert task.scanner == "cve-bin-tool"
    assert task.scanner_version == "3.4.1"
    # Vulnerability summary
    assert task.total_vulnerabilities == 2
    assert task.component_count == 1
    assert task.high_count == 1
    assert task.low_count == 1
    assert len(session.scalars(select(RpmScanVulnerability)).all()) == 2
    assert len(session.scalars(select(RpmScanComponent)).all()) == 1
    assert {row.name for row in task.artifacts} == {
        "scan-manifest.json",
        "scan-results.json",
        "scan-results.csv",
        "scan-results.html",
        "scan.log",
    }


def test_sync_task_treats_cbt_exit_code_one_as_finished(session):
    # cve-bin-tool returns 1 when vulnerabilities were found: still a success.
    artifacts, contents = rpm_scan_artifacts(exit_code=1)
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    task = _task(session)

    sync_task(session, client, task)

    assert task.cbt_exit_code == 1
    assert task.state == "FINISHED"
    assert task.total_vulnerabilities == 2


def test_sync_task_fails_when_scanner_reports_an_error(session):
    artifacts, contents = rpm_scan_artifacts(exit_code=2)
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    task = _task(session)

    sync_task(session, client, task)

    assert task.cbt_exit_code == 2
    assert task.state == "FAILED"


def test_sync_task_not_available_when_build_ended_without_results(session):
    client = FakeJenkinsClient()
    task = _task(session)

    sync_task(session, client, task)

    assert task.state == "NOT_AVAILABLE"
    assert task.sync_status == "ERROR"
    assert "no valid RPM scan manifest" in task.sync_error


def test_sync_task_keeps_running_while_build_is_building(session):
    client = FakeJenkinsClient(building=True)
    task = _task(session)

    sync_task(session, client, task)

    assert task.state == "RUNNING"
    assert task.sync_status == "PENDING"


def test_sync_task_ignores_artifacts_from_another_build(session):
    artifacts, contents = rpm_scan_artifacts(
        prefix=f"rpm-scan-artifacts/{RPM_BUILD_NUMBER + 1}/{RPM_SCAN_KEY}"
    )
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    task = _task(session)

    sync_task(session, client, task)

    assert task.state == "NOT_AVAILABLE"
    assert client.requested_artifacts == []
    assert task.artifacts == []


def test_sync_task_ignores_artifacts_from_another_scan_key(session):
    other_scan_key = "b" * 64
    artifacts, contents = rpm_scan_artifacts(
        prefix=f"rpm-scan-artifacts/{RPM_BUILD_NUMBER}/{other_scan_key}"
    )
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    task = _task(session)

    sync_task(session, client, task)

    assert task.state == "NOT_AVAILABLE"
    assert client.requested_artifacts == []
    assert task.artifacts == []


def test_sync_multiple_rpm_tasks_in_the_same_build(session):
    other_scan_key = "b" * 64
    first_artifacts, first_contents = rpm_scan_artifacts()
    second_artifacts, second_contents = rpm_scan_artifacts(
        prefix=f"rpm-scan-artifacts/{RPM_BUILD_NUMBER}/{other_scan_key}",
        sha256=other_scan_key,
    )
    client = FakeJenkinsClient(
        artifacts=first_artifacts + second_artifacts,
        contents={**first_contents, **second_contents},
    )
    first_task = _task(session)
    second_task = _task(session, scan_key=other_scan_key)

    sync_task(session, client, first_task)
    sync_task(session, client, second_task)

    assert first_task.state == "FINISHED"
    assert second_task.state == "FINISHED"
    assert {row.relative_path for row in first_task.artifacts} == set(
        first_contents
    )
    assert {row.relative_path for row in second_task.artifacts} == set(
        second_contents
    )


def test_sync_task_rejects_manifest_for_a_different_rpm(session):
    artifacts, contents = rpm_scan_artifacts(sha256="b" * 64)
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    task = _task(session)

    with pytest.raises(ValueError, match="checksum"):
        sync_task(session, client, task)


def test_sync_registered_tasks_only_resyncs_unfinished_tasks(
    session, settings, monkeypatch
):
    _task(session, build_number=1, state="FINISHED")
    _task(session, build_number=2, state="RUNNING")
    _task(session, build_number=3, state="NOT_AVAILABLE")
    _task(session, build_number=4, state="FAILED")
    client = FakeJenkinsClient()
    monkeypatch.setattr(resync_module, "JenkinsClient", lambda *args, **kwargs: client)

    result = sync_registered_tasks(settings, session)

    assert result == {"attempted": 2, "synced": 0, "pending": 0, "failed": 2}
    assert sorted(number for _, number in client.requested_builds) == [2, 3]
    assert client.closed is True
