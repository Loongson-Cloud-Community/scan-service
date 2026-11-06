from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy.orm import Session

from ....config import Settings
from ....jenkins import JenkinsClient
from ....scan_protocol import require_matching_identity
from ....scan_state import FAILED, NOT_AVAILABLE, RUNNING, accepts_event, is_terminal
from ....task_writes import ensure_locked_task, find_locked_task, lock_task
from ..models import RpmScanTask
from .synchronization import sync_task


def find_task(db: Session, values: dict[str, Any]) -> RpmScanTask | None:
    return find_locked_task(db, RpmScanTask, {
        key: values[key] for key in ("jenkins_job_full_name", "jenkins_build_number", "scan_key")
    })


def register_start(db: Session, values: dict[str, Any]) -> RpmScanTask:
    task = ensure_locked_task(db, RpmScanTask, {
        key: values[key] for key in ("jenkins_job_full_name", "jenkins_build_number", "scan_key")
    }, {
        "rpm_name": values["rpm_name"], "rpm_sha256": values["rpm_sha256"],
        "state": RUNNING, "sync_status": "PENDING",
    })
    require_matching_identity({"rpm_name": task.rpm_name, "rpm_sha256": task.rpm_sha256}, values)
    if accepts_event(task.state, "started", ended=task.finished_at is not None):
        task.created_at = (
            task.created_at or values.get("created_at") or datetime.now(timezone.utc)
        )
        task.state = RUNNING
    db.flush()
    return task


def record_completion(
    db: Session,
    task: RpmScanTask,
    values: dict[str, Any],
) -> RpmScanTask:
    """Record scan end without treating the event as validated results."""
    lock_task(db, task)
    if not accepts_event(task.state, "completed"):
        return task
    task.finished_at = (
        task.finished_at or values.get("finished_at") or datetime.now(timezone.utc)
    )
    if task.cbt_exit_code is None:
        task.cbt_exit_code = values.get("cbt_exit_code")
    task.sync_status = "PENDING"
    db.flush()
    return task


def complete_task(
    db: Session,
    settings: Settings,
    task: RpmScanTask,
    values: dict[str, Any] | None = None,
) -> RpmScanTask:
    task = record_completion(db, task, values or {})
    if is_terminal(task.state):
        return task
    identity = {key: getattr(task, key) for key in (
        "jenkins_job_full_name", "jenkins_build_number", "scan_key",
    )}
    db.commit()

    client = JenkinsClient(
        settings.jenkins_base_url,
        settings.jenkins_user,
        settings.jenkins_token,
        settings.request_timeout_seconds,
    )
    try:
        sync_task(db, client, task, settings.artifact_limits)
        db.commit()
    except Exception as exc:
        db.rollback()
        task = find_task(db, identity)
        if task is None:
            raise
        if is_terminal(task.state):
            return task
        task.state = NOT_AVAILABLE
        task.sync_status = "ERROR"
        task.sync_error = str(exc)[:4000]
        task.last_synced_at = datetime.now(timezone.utc)
        db.commit()
    finally:
        client.close()
    return task


def fail_task(db: Session, task: RpmScanTask, values: dict[str, Any]) -> RpmScanTask:
    lock_task(db, task)
    if not accepts_event(task.state, "failed"):
        return task
    task.state = FAILED
    task.finished_at = (
        task.finished_at or values.get("finished_at") or datetime.now(timezone.utc)
    )
    task.cbt_exit_code = values.get("cbt_exit_code")
    task.sync_status = "SYNCED"
    task.sync_error = None
    return task
