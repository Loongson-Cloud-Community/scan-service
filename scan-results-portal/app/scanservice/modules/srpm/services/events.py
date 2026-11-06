from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ....config import Settings
from ....jenkins import JenkinsClient
from ....scan_protocol import require_matching_identity
from ....scan_state import FAILED, NOT_AVAILABLE, RUNNING, accepts_event, is_terminal
from ....task_writes import ensure_locked_task, find_locked_task, lock_task
from ..models import SrpmScanTask
from .synchronization import sync_build


def _job_name(settings: Settings, values: dict[str, Any]) -> str:
    job = str(values.get("jenkins_job_full_name") or "")
    if not job:
        raise ValueError("Jenkins job is required")
    return job


def find_task(db: Session, job: str, build_number: int) -> SrpmScanTask | None:
    return find_locked_task(db, SrpmScanTask, {
        "jenkins_job_full_name": job, "jenkins_build_number": build_number,
    })


def _ensure_task(
    db: Session, settings: Settings, values: dict[str, Any]
) -> SrpmScanTask:
    job = _job_name(settings, values)
    build_number = int(values["jenkins_build_number"])
    task = ensure_locked_task(db, SrpmScanTask, {
        "jenkins_job_full_name": job, "jenkins_build_number": build_number,
    }, {
        "lifecycle_state": "DISCOVERED", "scan_result": NOT_AVAILABLE,
        "gate_result": "NOT_EVALUATED", "sync_status": "PENDING",
    })
    require_matching_identity({"srpm_name": task.srpm_name}, values)
    return task


def register_start(
    db: Session, settings: Settings, values: dict[str, Any]
) -> SrpmScanTask:
    task = _ensure_task(db, settings, values)
    if not accepts_event(
        task.scan_result,
        "started",
        ended=task.finished_at is not None or task.scan_finished_at is not None,
    ):
        return task
    occurred_at = values.get("created_at") or datetime.now(timezone.utc)
    task.srpm_name = task.srpm_name or values.get("srpm_name")
    task.lifecycle_state = RUNNING
    task.scan_result = RUNNING
    task.created_at = task.created_at or occurred_at
    task.started_at = task.started_at or occurred_at
    task.scan_started_at = task.scan_started_at or occurred_at
    db.flush()
    return task


def record_completion(
    db: Session,
    task: SrpmScanTask,
    finished_at: datetime | None = None,
    exit_code: int | None = None,
) -> SrpmScanTask:
    """Record scan end without treating the event as validated results."""
    lock_task(db, task)
    if not accepts_event(task.scan_result, "completed"):
        return task
    ended_at = (
        task.scan_finished_at or task.finished_at or finished_at or datetime.now(timezone.utc)
    )
    task.scan_finished_at = task.scan_finished_at or ended_at
    task.finished_at = task.finished_at or ended_at
    task.sync_status = "PENDING"
    if task.csmock_exit_code is None and exit_code is not None:
        task.csmock_exit_code = exit_code
    db.flush()
    return task


def complete_task(
    db: Session,
    settings: Settings,
    task: SrpmScanTask,
    finished_at: datetime | None = None,
    exit_code: int | None = None,
) -> SrpmScanTask:
    task = record_completion(db, task, finished_at, exit_code)
    if is_terminal(task.scan_result):
        return task
    db.commit()

    client = JenkinsClient(
        settings.jenkins_base_url,
        settings.jenkins_user,
        settings.jenkins_token,
        settings.request_timeout_seconds,
    )
    try:
        sync_build(
            db,
            client,
            settings,
            task.jenkins_build_number,
            job_full_name=task.jenkins_job_full_name,
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        task = find_task(db, task.jenkins_job_full_name, task.jenkins_build_number)
        if task is None:
            raise
        if is_terminal(task.scan_result):
            return task
        task.scan_result = NOT_AVAILABLE
        task.sync_status = "ERROR"
        task.sync_error = str(exc)[:4000]
        task.last_synced_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        client.close()
    return task


def fail_task(
    db: Session,
    settings: Settings,
    task: SrpmScanTask,
    finished_at: datetime | None = None,
    exit_code: int | None = None,
) -> SrpmScanTask:
    lock_task(db, task)
    if not accepts_event(task.scan_result, "failed"):
        return task
    ended_at = (
        task.scan_finished_at or task.finished_at or finished_at or datetime.now(timezone.utc)
    )
    task.scan_result = FAILED
    task.scan_finished_at = task.scan_finished_at or ended_at
    task.finished_at = task.finished_at or ended_at
    task.sync_status = "SYNCED"
    task.sync_error = None
    if exit_code is not None:
        task.csmock_exit_code = exit_code
    return task
