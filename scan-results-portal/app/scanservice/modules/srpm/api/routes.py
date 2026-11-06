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
from ..schemas.events import SrpmEventRequest
from ..services.artifacts import (
    archive_member_response,
    artifact_response,
    get_artifact_row,
)
from ..services.events import complete_task, fail_task, find_task, record_completion, register_start
from ..services.synchronization import sync_registered_tasks
from ..services.task_queries import (
    get_artifact_task, get_task_metadata, list_task_findings_page,
    list_task_metadata_page, list_task_summaries,
)
from ..services.task_service import task_payload


router = APIRouter(prefix="/api/v1/srpm", tags=["srpm"])


@router.post("/events")
def receive_event(
    payload: SrpmEventRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _: None = Depends(require_ingest_token),
) -> dict[str, Any]:
    settings = get_settings()
    values = payload.dict(exclude_unset=True)
    try:
        task = find_task(
            db,
            payload.jenkins_job_full_name,
            payload.jenkins_build_number,
        )
        if task is None or payload.event == "started":
            task = register_start(db, settings, values)
        require_matching_identity({"srpm_name": task.srpm_name}, values)
    except ScanIdentityConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if payload.event == "started":
        db.commit()
    else:
        if payload.event == "completed":
            task = record_completion(
                db,
                task,
                payload.finished_at,
                payload.csmock_exit_code,
            )
            db.commit()
            if not is_terminal(task.scan_result):
                background_tasks.add_task(
                    synchronize_completion, settings, type(task), task.id, complete_task,
                )
        elif payload.event == "failed":
            task = fail_task(
                db,
                settings,
                task,
                payload.finished_at,
                payload.csmock_exit_code,
            )
            db.commit()
        else:
            raise HTTPException(status_code=422, detail="unsupported SRPM event")
    return task_payload(task)


@router.get("/tasks")
def list_tasks(
    search: str | None = None,
    scan_result: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    total, rows = list_task_metadata_page(db, search, scan_result, page, page_size)
    return {
        "page": page,
        "page_size": page_size,
        "total": total,
        "items": [task_payload(row) for row in rows],
    }


@router.get("/tasks/{task_id}")
def task_detail(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    return task_payload(get_task_metadata(db, task_id))


@router.get("/tasks/{task_id}/summary")
def task_summary(task_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [
        {"checker": row.checker, "issue_type": row.issue_type, "count": row.count}
        for row in list_task_summaries(db, task_id)
    ]


@router.get("/tasks/{task_id}/findings")
def task_findings(
    task_id: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    total, rows = list_task_findings_page(db, task_id, page, page_size)
    items = [
        {
            "id": row.id,
            "fingerprint": row.fingerprint,
            "checker": row.checker,
            "rule_id": row.rule_id,
            "severity": row.severity,
            "message": row.message,
            "file_path": row.file_path,
            "line": row.line,
            "column": row.column,
            "code_context": row.code_context,
            "raw": row.raw,
        }
        for row in rows
    ]
    return {"page": page, "page_size": page_size, "total": total, "items": items}


@router.get("/tasks/{task_id}/artifacts")
def task_artifacts(task_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    task = get_artifact_task(db, task_id)
    return [
        {
            "id": row.id,
            "name": row.name,
            "artifact_type": row.artifact_type,
            "relative_path": row.relative_path,
            "size_bytes": row.size_bytes,
        }
        for row in task.artifacts
    ]


@router.get("/tasks/{task_id}/artifacts/{artifact_id}/view")
def view_artifact(task_id: int, artifact_id: int, db: Session = Depends(get_db)) -> Response:
    task = get_artifact_task(db, task_id)
    return artifact_response(task, get_artifact_row(task, artifact_id), download=False)


@router.get("/tasks/{task_id}/artifacts/{artifact_id}/download")
def download_artifact(task_id: int, artifact_id: int, db: Session = Depends(get_db)) -> Response:
    task = get_artifact_task(db, task_id)
    return artifact_response(task, get_artifact_row(task, artifact_id), download=True)


@router.get("/tasks/{task_id}/archive/{archive_ref:path}")
def archive_member(
    task_id: int, archive_ref: str, db: Session = Depends(get_db)
) -> Response:
    return archive_member_response(get_artifact_task(db, task_id), archive_ref)


@router.post("/sync")
def sync_tasks(
    db: Session = Depends(get_db),
    _: None = Depends(require_operator_token),
) -> dict[str, Any]:
    try:
        return sync_registered_tasks(get_settings(), db)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
