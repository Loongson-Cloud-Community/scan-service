"""Bounded reconciliation of registered RPM and SRPM scans.

The oldest outstanding attempt runs first. A never-attempted scan uses its
portal registration time, so continuous arrivals cannot jump ahead of older
retries. Scan-specific state and result handling stay in the supplied adapter.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .config import Settings
from .jenkins import JenkinsClient
from .scan_state import is_terminal
from .task_writes import lock_task


TaskSync = Callable[[Session, JenkinsClient, Settings, Any], Any]


def resync_registered_tasks(
    settings: Settings,
    db: Session,
    *,
    model: type[Any],
    state_column: Any,
    active_states: Iterable[str],
    sync_one: TaskSync,
) -> dict[str, int]:
    """Reconcile one fair batch; persist its attempt times across requests."""
    tasks = db.scalars(
        select(model)
        .where(state_column.in_(tuple(active_states)))
        .order_by(
            func.coalesce(model.last_synced_at, model.created_at_service).asc(),
            model.id.asc(),
        )
        .limit(settings.recent_build_limit)
    ).all()

    client = JenkinsClient(
        settings.jenkins_base_url,
        settings.jenkins_user,
        settings.jenkins_token,
        settings.request_timeout_seconds,
    )
    counts = {"attempted": 0, "synced": 0, "pending": 0, "failed": 0}
    try:
        for task in tasks:
            counts["attempted"] += 1
            try:
                sync_one(db, client, settings, task)
                # Scheduling progress belongs here, including adapters that
                # leave the scan pending without producing any results yet.
                task.last_synced_at = datetime.now(timezone.utc)
                if task.sync_status == "ERROR":
                    outcome = "failed"
                elif task.sync_status == "SYNCED" and is_terminal(
                    getattr(task, state_column.key)
                ):
                    # A known scanner failure is still a synchronized fact.
                    outcome = "synced"
                else:
                    outcome = "pending"
                db.commit()
                counts[outcome] += 1
            except Exception as exc:
                db.rollback()
                current = db.get(model, task.id)
                if current is not None:
                    lock_task(db, current)
                    if not is_terminal(getattr(current, state_column.key)):
                        current.sync_status = "ERROR"
                        current.sync_error = str(exc)[:4000]
                        current.last_synced_at = datetime.now(timezone.utc)
                    db.commit()
                counts["failed"] += 1
    finally:
        client.close()
    return counts
