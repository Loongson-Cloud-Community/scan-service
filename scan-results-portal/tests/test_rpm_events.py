from datetime import datetime, timezone

from sqlalchemy import select

from conftest import RPM_SCAN_KEY, FakeJenkinsClient, rpm_scan_artifacts

from scanservice.modules.rpm.models import RpmScanTask
from scanservice.modules.rpm.services import events
from scanservice.modules.rpm.services.events import (
    complete_task,
    fail_task,
    register_start,
)


STARTED_AT = datetime(2026, 10, 1, 2, 0, tzinfo=timezone.utc)
FINISHED_AT = datetime(2026, 10, 1, 2, 5, tzinfo=timezone.utc)


def _values(**overrides):
    values = {
        "scan_key": RPM_SCAN_KEY,
        "jenkins_job_full_name": "rpm-docker-test",
        "jenkins_build_number": 7,
        "rpm_name": "docker-24.0.9-8.lns23.loongarch64.rpm",
        "rpm_sha256": RPM_SCAN_KEY,
    }
    values.update(overrides)
    return values


def test_register_start_creates_running_task(session):
    task = register_start(session, _values(created_at=STARTED_AT))
    session.commit()

    assert task.state == "RUNNING"
    assert task.sync_status == "PENDING"
    assert task.rpm_name == "docker-24.0.9-8.lns23.loongarch64.rpm"
    assert task.rpm_sha256 == RPM_SCAN_KEY
    assert task.created_at is not None


def test_register_start_is_idempotent_for_the_same_build(session):
    first = register_start(session, _values())
    session.commit()
    second = register_start(session, _values())
    session.commit()

    assert first.id == second.id
    assert session.scalars(select(RpmScanTask)).all() == [second]


def test_register_start_preserves_a_terminal_state(session):
    task = register_start(session, _values())
    session.commit()
    fail_task(session, task, {"cbt_exit_code": 2})
    session.commit()

    retried = register_start(session, _values())
    session.commit()

    assert retried.state == "FAILED"
    assert retried.cbt_exit_code == 2


def test_fail_task_records_exit_code(session):
    task = register_start(session, _values())
    session.commit()

    fail_task(
        session,
        task,
        {"cbt_exit_code": 2, "finished_at": FINISHED_AT},
    )
    session.commit()

    assert task.state == "FAILED"
    assert task.cbt_exit_code == 2
    assert task.sync_status == "SYNCED"
    assert task.sync_error is None
    assert task.finished_at is not None


def test_complete_task_reaches_finished_on_valid_artifacts(
    session, settings, monkeypatch
):
    artifacts, contents = rpm_scan_artifacts(exit_code=0)
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    monkeypatch.setattr(events, "JenkinsClient", lambda *args, **kwargs: client)
    task = register_start(session, _values())
    session.commit()

    complete_task(
        session,
        settings,
        task,
        {**_values(), "finished_at": FINISHED_AT, "cbt_exit_code": 0},
    )

    assert task.state == "FINISHED"
    assert client.closed is True


def test_complete_task_marks_not_available_when_jenkins_is_unreachable(
    session, settings, monkeypatch
):
    client = FakeJenkinsClient()

    def explode(job_name, number):
        raise RuntimeError("jenkins is down")

    client.get_build = explode
    monkeypatch.setattr(events, "JenkinsClient", lambda *args, **kwargs: client)
    task = register_start(session, _values())
    session.commit()

    complete_task(session, settings, task, {**_values(), "finished_at": FINISHED_AT})

    assert task.state == "NOT_AVAILABLE"
    assert task.sync_status == "ERROR"
    assert "jenkins is down" in task.sync_error
