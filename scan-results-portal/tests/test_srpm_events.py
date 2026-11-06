from datetime import datetime, timezone

from sqlalchemy import select

from conftest import FakeJenkinsClient, srpm_scan_artifacts

from scanservice.modules.srpm.models import SrpmScanTask
from scanservice.modules.srpm.services import events
from scanservice.modules.srpm.services.events import (
    complete_task,
    fail_task,
    register_start,
)


STARTED_AT = datetime(2026, 10, 1, 2, 0, tzinfo=timezone.utc)
FINISHED_AT = datetime(2026, 10, 1, 2, 5, tzinfo=timezone.utc)


def _values(**overrides):
    values = {
        "jenkins_job_full_name": "csmock-curl-test",
        "jenkins_build_number": 6,
        "srpm_name": "curl-8.4.0-9.ocs23.src.rpm",
    }
    values.update(overrides)
    return values


def test_register_start_creates_running_task(session, settings):
    task = register_start(
        session, settings, _values(created_at=STARTED_AT)
    )
    session.commit()

    assert task.scan_result == "RUNNING"
    assert task.lifecycle_state == "RUNNING"
    assert task.srpm_name == "curl-8.4.0-9.ocs23.src.rpm"
    assert task.created_at is not None
    assert task.started_at is not None


def test_register_start_is_idempotent_for_the_same_build(session, settings):
    first = register_start(session, settings, _values())
    session.commit()
    second = register_start(session, settings, _values())
    session.commit()

    assert first.id == second.id
    assert session.scalars(select(SrpmScanTask)).all() == [second]


def test_register_start_preserves_a_terminal_scan_result(session, settings):
    task = register_start(session, settings, _values())
    session.commit()
    fail_task(session, settings, task, None, 2)
    session.commit()

    retried = register_start(session, settings, _values())
    session.commit()

    assert retried.scan_result == "FAILED"
    assert retried.csmock_exit_code == 2


def test_fail_task_records_exit_code(session, settings):
    task = register_start(session, settings, _values())
    session.commit()

    fail_task(session, settings, task, FINISHED_AT, 2)
    session.commit()

    assert task.scan_result == "FAILED"
    assert task.csmock_exit_code == 2
    assert task.sync_status == "SYNCED"
    assert task.sync_error is None
    assert task.finished_at is not None


def test_complete_task_reaches_finished_on_valid_archive(
    session, settings, monkeypatch
):
    artifacts, contents = srpm_scan_artifacts()
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    monkeypatch.setattr(events, "JenkinsClient", lambda *args, **kwargs: client)
    task = register_start(session, settings, _values())
    session.commit()

    complete_task(session, settings, task, FINISHED_AT, 0)

    assert task.scan_result == "FINISHED"
    assert client.closed is True


def test_complete_task_marks_not_available_when_jenkins_is_unreachable(
    session, settings, monkeypatch
):
    client = FakeJenkinsClient()

    def explode(job_name, number):
        raise RuntimeError("jenkins is down")

    client.get_build = explode
    monkeypatch.setattr(events, "JenkinsClient", lambda *args, **kwargs: client)
    task = register_start(session, settings, _values())
    session.commit()

    complete_task(session, settings, task, FINISHED_AT, 0)

    assert task.scan_result == "NOT_AVAILABLE"
    assert task.sync_status == "ERROR"
    assert "jenkins is down" in task.sync_error
