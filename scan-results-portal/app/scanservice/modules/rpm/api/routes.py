from __future__ import annotations

from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ....config import get_settings
from ....completion_sync import synchronize_completion
from ....db import get_db
from ....scan_protocol import ScanIdentityConflict, require_matching_identity
from ....scan_state import is_terminal
from ....security import require_ingest_token, require_operator_token
from ..schemas.events import RpmEventRequest
from ..services.artifacts import artifact_response, get_artifact
from ..services.events import complete_task, fail_task, find_task, record_completion, register_start
from ..services.synchronization import sync_registered_tasks
from ..services.task_queries import get_artifact_task, get_task_metadata, list_task_metadata_page
from ..services.task_service import task_payload


router = APIRouter(prefix="/api/v1/rpm", tags=["rpm"])


@router.post("/events")
def receive_event(
    payload: RpmEventRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: None = Depends(require_ingest_token),
) -> dict[str, Any]:
    settings = get_settings()
    values = payload.dict(exclude_unset=True)
    try:
        task = find_task(db, values)
        if task is None or payload.event == "started":
            task = register_start(db, values)
        require_matching_identity({
            "rpm_name": task.rpm_name, "rpm_sha256": task.rpm_sha256,
        }, values)
    except ScanIdentityConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if payload.event == "started":
        db.commit()
    else:
        if payload.event == "completed":
            task = record_completion(db, task, values)
            db.commit()
            if not is_terminal(task.state):
                background_tasks.add_task(
                    synchronize_completion, settings, type(task), task.id, complete_task,
                )
        elif payload.event == "failed":
            task = fail_task(db, task, values)
            db.commit()
        else:
            raise HTTPException(status_code=422, detail="unsupported RPM event")
    return task_payload(task)


@router.get("/tasks")
def list_tasks(
    search: str | None = None,
    state: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    total, tasks = list_task_metadata_page(db, search, state, page, page_size)
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [task_payload(task) for task in tasks],
    }


@router.get("/tasks/{task_id}")
def task_detail(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    return task_payload(get_task_metadata(db, task_id))


@router.post("/sync")
def sync_tasks(
    db: Session = Depends(get_db),
    _: None = Depends(require_operator_token),
) -> dict[str, int]:
    return sync_registered_tasks(get_settings(), db)


@router.get("/tasks/{task_id}/artifacts/{artifact_id}/view")
def view_artifact(
    task_id: int,
    artifact_id: int,
    db: Session = Depends(get_db),
) -> Response:
    task = get_artifact_task(db, task_id)
    return artifact_response(task, get_artifact(task, artifact_id), download=False)


@router.get("/tasks/{task_id}/artifacts/{artifact_id}/download")
def download_artifact(
    task_id: int,
    artifact_id: int,
    db: Session = Depends(get_db),
) -> Response:
    task = get_artifact_task(db, task_id)
    return artifact_response(task, get_artifact(task, artifact_id), download=True)
