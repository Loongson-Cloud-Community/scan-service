from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from conftest import (
    RPM_BUILD_NUMBER, RPM_SCAN_KEY, SRPM_BUILD_NUMBER, FakeJenkinsClient,
    rpm_scan_artifacts, srpm_scan_artifacts,
)
from scanservice.modules.rpm.services import events as rpm_events
from scanservice.modules.rpm.services.synchronization import sync_task
from scanservice.modules.srpm.services import events as srpm_events
from scanservice.modules.srpm.services.synchronization import sync_build
from scanservice.scan_protocol import ScanIdentityConflict


STARTED_AT = datetime(2026, 10, 1, 2, 0, tzinfo=timezone.utc)
FINISHED_AT = STARTED_AT + timedelta(minutes=5)


@pytest.fixture(params=["rpm", "srpm"])
def scan(request, session, settings, monkeypatch):
    kind = request.param
    if kind == "rpm":
        module = rpm_events
        artifacts, contents = rpm_scan_artifacts()
        values = {
            "jenkins_job_full_name": "demo",
            "jenkins_build_number": RPM_BUILD_NUMBER,
            "scan_key": RPM_SCAN_KEY,
            "rpm_sha256": RPM_SCAN_KEY,
            "rpm_name": "docker-24.0.9-8.lns23.loongarch64.rpm",
        }
        state_field, exit_field, label_field = "state", "cbt_exit_code", "rpm_name"
    else:
        module = srpm_events
        artifacts, contents = srpm_scan_artifacts()
        values = {
            "jenkins_job_full_name": "demo",
            "jenkins_build_number": SRPM_BUILD_NUMBER,
            "srpm_name": "curl-8.4.0-9.ocs23.src.rpm",
        }
        state_field, exit_field, label_field = "scan_result", "csmock_exit_code", "srpm_name"
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    monkeypatch.setattr(module, "JenkinsClient", lambda *args, **kwargs: client)

    def start(**overrides):
        incoming = {**values, "created_at": STARTED_AT, **overrides}
        if kind == "rpm":
            task = module.register_start(session, incoming)
        else:
            task = module.register_start(session, settings, incoming)
        session.commit()
        return task

    task = start()

    def complete(ended_at=FINISHED_AT, exit_code=0):
        if kind == "rpm":
            return module.complete_task(session, settings, task, {
                **values, "finished_at": ended_at, "cbt_exit_code": exit_code,
            })
        return module.complete_task(session, settings, task, ended_at, exit_code)

    def fail(ended_at=FINISHED_AT, exit_code=2):
        if kind == "rpm":
            module.fail_task(session, task, {
                "finished_at": ended_at, "cbt_exit_code": exit_code,
            })
        else:
            module.fail_task(session, settings, task, ended_at, exit_code)
        session.commit()

    def sync():
        if kind == "rpm":
            sync_task(session, client, task)
        else:
            sync_build(session, client, settings, task.jenkins_build_number, "demo")
        session.commit()

    def snapshot():
        session.refresh(task)
        fields = [
            state_field, exit_field, label_field, "created_at", "finished_at",
            "sync_status", "sync_error", "last_synced_at",
        ]
        if kind == "rpm":
            fields += ["total_vulnerabilities", "high_count", "low_count"]
        else:
            fields += ["started_at", "scan_started_at", "scan_finished_at", "total_findings"]
        return {field: getattr(task, field) for field in fields}

    return SimpleNamespace(
        task=task, client=client, start=start, complete=complete, fail=fail, sync=sync,
        snapshot=snapshot, state=lambda: getattr(task, state_field),
        label_field=label_field, artifacts=artifacts, contents=contents,
    )


@pytest.mark.parametrize("terminal", ["FINISHED", "FAILED"])
@pytest.mark.parametrize("later_event", ["started", "completed", "failed", "sync"])
def test_terminal_decision_survives_later_events(scan, terminal, later_event):
    if terminal == "FINISHED":
        scan.complete()
    else:
        scan.fail()
    assert scan.state() == terminal
    original = scan.snapshot()
    builds_read = list(scan.client.requested_builds)

    def unavailable(*args):
        raise RuntimeError("temporary Jenkins outage")

    scan.client.get_build = unavailable
    later = FINISHED_AT + timedelta(hours=1)
    if later_event == "started":
        scan.start(created_at=later)
    elif later_event == "completed":
        scan.complete(later, exit_code=0 if terminal == "FAILED" else 2)
    elif later_event == "failed":
        scan.fail(later)
    else:
        scan.sync()

    assert scan.snapshot() == original
    assert scan.client.requested_builds == builds_read


def test_late_started_preserves_unavailable_result_and_finish_time(scan):
    scan.client.artifacts = []
    scan.complete()
    assert scan.state() == "NOT_AVAILABLE"
    original = scan.snapshot()

    scan.start(created_at=FINISHED_AT)

    assert scan.snapshot() == original


def test_unavailable_result_can_recover_when_artifacts_arrive(scan):
    scan.client.artifacts = []
    scan.complete()
    assert scan.state() == "NOT_AVAILABLE"
    scan.client.artifacts = scan.artifacts

    scan.complete()

    assert scan.state() == "FINISHED"


def test_ended_scan_without_artifacts_does_not_revert_to_running(scan):
    scan.client.building = True
    scan.client.artifacts = []

    scan.complete()
    scan.sync()

    assert scan.state() == "NOT_AVAILABLE"
    assert scan.task.finished_at is not None


@pytest.mark.parametrize("scan", ["srpm"], indirect=True)
def test_srpm_finish_time_alone_preserves_ended_evidence(scan):
    scan.client.building = True
    scan.client.artifacts = []
    scan.complete()
    scan.task.scan_finished_at = None

    scan.sync()

    assert scan.state() == "NOT_AVAILABLE"
    assert scan.task.finished_at is not None


def test_repeated_start_preserves_original_time_and_label(scan):
    original = scan.snapshot()

    scan.start(created_at=FINISHED_AT)

    assert scan.snapshot() == original


def test_conflicting_start_is_rejected_without_changing_task(scan):
    original = scan.snapshot()
    with pytest.raises(ScanIdentityConflict):
        scan.start(created_at=FINISHED_AT, **{scan.label_field: "different.rpm"})
    assert scan.snapshot() == original


def test_completed_retry_keeps_the_original_finish_time(scan):
    scan.client.artifacts = []
    scan.complete()
    original_finished_at = scan.snapshot()["finished_at"]
    scan.client.artifacts = scan.artifacts

    scan.complete(FINISHED_AT + timedelta(hours=1))

    assert scan.state() == "FINISHED"
    assert scan.snapshot()["finished_at"] == original_finished_at


def test_sync_failure_does_not_overwrite_a_new_terminal_decision(scan):
    decided = {}

    def fail_during_read(*args):
        scan.fail(FINISHED_AT + timedelta(minutes=1))
        decided.update(scan.snapshot())
        raise RuntimeError("temporary Jenkins outage")

    scan.client.get_build = fail_during_read
    scan.complete()

    assert scan.snapshot() == decided
