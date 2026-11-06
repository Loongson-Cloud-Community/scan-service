"""Purpose-specific SRPM reads; summaries never load findings or artifacts."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, load_only, raiseload, selectinload

from ..models import SrpmScanArtifact, SrpmScanFinding, SrpmScanSummary, SrpmScanTask
from .task_service import TASK_PAYLOAD_FIELDS


WEB_LIST_FIELDS = (
    "id", "scan_metadata", "srpm_name", "nvr", "scan_result",
    "total_findings", "created_at", "finished_at",
)
WEB_DETAIL_FIELDS = (
    "id", "srpm_name", "nvr", "scan_result", "triggered_by", "created_at", "finished_at",
    "scan_metadata", "enabled_plugins", "mock_config", "total_findings",
)


def _read_task(
    db: Session, task_id: int, fields: tuple[str, ...], *relationships,
) -> SrpmScanTask:
    task = db.scalar(
        select(SrpmScanTask)
        .options(
            load_only(*(getattr(SrpmScanTask, name) for name in fields), raiseload=True),
            raiseload("*"),
            *relationships,
        )
        .where(SrpmScanTask.id == task_id)
    )
    if task is None:
        raise HTTPException(status_code=404, detail="scan task not found")
    return task


def get_task_metadata(db: Session, task_id: int) -> SrpmScanTask:
    return _read_task(db, task_id, TASK_PAYLOAD_FIELDS)


def get_task_detail(db: Session, task_id: int) -> SrpmScanTask:
    return _read_task(
        db, task_id, WEB_DETAIL_FIELDS,
        selectinload(SrpmScanTask.artifacts).load_only(
            SrpmScanArtifact.id, SrpmScanArtifact.name, raiseload=True,
        ),
        selectinload(SrpmScanTask.summaries).load_only(
            SrpmScanSummary.checker, SrpmScanSummary.issue_type, SrpmScanSummary.count,
            raiseload=True,
        ),
    )


def list_task_summaries(db: Session, task_id: int) -> list[SrpmScanSummary]:
    _read_task(db, task_id, ("id",))
    return db.scalars(
        select(SrpmScanSummary)
        .options(
            load_only(SrpmScanSummary.checker, SrpmScanSummary.issue_type,
                      SrpmScanSummary.count, raiseload=True),
            raiseload("*"),
        )
        .where(SrpmScanSummary.task_id == task_id)
    ).all()


def list_task_findings_page(
    db: Session, task_id: int, page: int, page_size: int,
) -> tuple[int, list[SrpmScanFinding]]:
    _read_task(db, task_id, ("id",))
    total = db.scalar(select(func.count()).select_from(SrpmScanFinding).where(
        SrpmScanFinding.task_id == task_id,
    )) or 0
    offset = (page - 1) * page_size
    if offset >= total:
        return total, []
    rows = db.scalars(
        select(SrpmScanFinding)
        .options(
            load_only(
                SrpmScanFinding.id, SrpmScanFinding.fingerprint, SrpmScanFinding.checker,
                SrpmScanFinding.rule_id, SrpmScanFinding.severity, SrpmScanFinding.message,
                SrpmScanFinding.file_path, SrpmScanFinding.line, SrpmScanFinding.column,
                SrpmScanFinding.code_context, SrpmScanFinding.raw, raiseload=True,
            ),
            raiseload("*"),
        )
        .where(SrpmScanFinding.task_id == task_id)
        .order_by(SrpmScanFinding.id)
        .offset(offset).limit(page_size)
    ).all()
    return total, rows


def get_artifact_task(db: Session, task_id: int) -> SrpmScanTask:
    """Read delivery metadata, including archive references, without findings."""
    task = db.scalar(
        select(SrpmScanTask)
        .options(
            load_only(
                SrpmScanTask.id,
                SrpmScanTask.jenkins_job_full_name,
                SrpmScanTask.jenkins_build_number,
                raiseload=True,
            ),
            selectinload(SrpmScanTask.artifacts).load_only(
                SrpmScanArtifact.id,
                SrpmScanArtifact.task_id,
                SrpmScanArtifact.name,
                SrpmScanArtifact.artifact_type,
                SrpmScanArtifact.relative_path,
                SrpmScanArtifact.size_bytes,
                raiseload=True,
            ),
            raiseload("*"),
        )
        .where(SrpmScanTask.id == task_id)
    )
    if task is None:
        raise HTTPException(status_code=404, detail="scan task not found")
    return task


def _list_task_page(
    db: Session, search: str | None, state: str | None,
    page: int, page_size: int, fields: tuple[str, ...],
) -> tuple[int, list[SrpmScanTask]]:
    filters = []
    if search:
        term = f"%{search}%"
        filters.append(or_(SrpmScanTask.srpm_name.ilike(term), SrpmScanTask.nvr.ilike(term)))
    if state:
        filters.append(SrpmScanTask.scan_result == state.upper())
    total = db.scalar(select(func.count()).select_from(SrpmScanTask).where(*filters)) or 0
    rows = db.scalars(
        select(SrpmScanTask)
        .options(
            load_only(*(getattr(SrpmScanTask, name) for name in fields), raiseload=True),
            raiseload("*"),
        )
        .where(*filters)
        .order_by(desc(SrpmScanTask.created_at), desc(SrpmScanTask.id))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return total, rows


def list_task_metadata_page(
    db: Session, search: str | None, state: str | None, page: int, page_size: int,
) -> tuple[int, list[SrpmScanTask]]:
    return _list_task_page(db, search, state, page, page_size, TASK_PAYLOAD_FIELDS)


def list_task_web_page(
    db: Session, search: str | None, state: str | None, page: int, page_size: int,
) -> tuple[int, list[SrpmScanTask]]:
    return _list_task_page(db, search, state, page, page_size, WEB_LIST_FIELDS)
