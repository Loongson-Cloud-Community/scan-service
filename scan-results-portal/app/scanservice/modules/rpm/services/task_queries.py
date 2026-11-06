"""Purpose-specific RPM reads with explicit column and relationship budgets."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, load_only, raiseload, selectinload

from ..models import RpmScanArtifact, RpmScanComponent, RpmScanTask, RpmScanVulnerability
from .task_service import TASK_PAYLOAD_FIELDS


WEB_LIST_FIELDS = (
    "id", "scanner", "rpm_name", "state", "total_vulnerabilities",
    "critical_count", "high_count", "medium_count", "low_count", "created_at", "finished_at",
)
WEB_DETAIL_FIELDS = (
    "id", "rpm_name", "name", "epoch", "version", "release", "architecture", "source_rpm",
    "scanner", "scanner_version", "scanner_args", "state", "triggered_by", "created_at",
    "finished_at", "total_vulnerabilities", "critical_count", "high_count",
    "medium_count", "low_count", "unknown_count",
)


def _read_task(
    db: Session, task_id: int, fields: tuple[str, ...], *relationships,
) -> RpmScanTask:
    task = db.scalar(
        select(RpmScanTask)
        .options(
            load_only(*(getattr(RpmScanTask, name) for name in fields), raiseload=True),
            raiseload("*"),
            *relationships,
        )
        .where(RpmScanTask.id == task_id)
    )
    if task is None:
        raise HTTPException(status_code=404, detail="RPM scan task not found")
    return task


def get_task_metadata(db: Session, task_id: int) -> RpmScanTask:
    return _read_task(db, task_id, TASK_PAYLOAD_FIELDS)


def get_task_detail(db: Session, task_id: int) -> RpmScanTask:
    task = _read_task(
        db, task_id, WEB_DETAIL_FIELDS,
        selectinload(RpmScanTask.artifacts).load_only(
            RpmScanArtifact.id, RpmScanArtifact.name, raiseload=True,
        ),
    )
    task.artifacts.sort(key=lambda row: row.name)
    return task


def list_task_components_page(
    db: Session, task_id: int, page: int, page_size: int,
) -> tuple[int, list[RpmScanComponent]]:
    """Read a page after the detail reader has checked that the task exists."""
    total = db.scalar(select(func.count()).select_from(RpmScanComponent).where(
        RpmScanComponent.task_id == task_id,
    )) or 0
    offset = (page - 1) * page_size
    if offset >= total:
        return total, []
    rows = db.scalars(
        select(RpmScanComponent)
        .options(
            load_only(RpmScanComponent.vendor, RpmScanComponent.product,
                      RpmScanComponent.version, RpmScanComponent.vulnerability_count,
                      raiseload=True),
            raiseload("*"),
        )
        .where(RpmScanComponent.task_id == task_id)
        .order_by(RpmScanComponent.vendor, RpmScanComponent.product,
                  RpmScanComponent.version, RpmScanComponent.id)
        .offset(offset).limit(page_size)
    ).all()
    return total, rows


def list_task_vulnerabilities_page(
    db: Session, task_id: int, page: int, page_size: int,
) -> tuple[int, list[RpmScanVulnerability]]:
    """Page detail records, not the distinct CVEs counted in the task summary."""
    total = db.scalar(select(func.count()).select_from(RpmScanVulnerability).where(
        RpmScanVulnerability.task_id == task_id,
    )) or 0
    offset = (page - 1) * page_size
    if offset >= total:
        return total, []
    rows = db.scalars(
        select(RpmScanVulnerability)
        .options(
            load_only(
                RpmScanVulnerability.id, RpmScanVulnerability.cve_number,
                RpmScanVulnerability.severity, RpmScanVulnerability.score,
                RpmScanVulnerability.vendor, RpmScanVulnerability.product,
                RpmScanVulnerability.version, RpmScanVulnerability.source,
                RpmScanVulnerability.description, RpmScanVulnerability.paths,
                RpmScanVulnerability.cvss_vector, raiseload=True,
            ),
            raiseload("*"),
        )
        .where(RpmScanVulnerability.task_id == task_id)
        .order_by(RpmScanVulnerability.severity, RpmScanVulnerability.cve_number,
                  RpmScanVulnerability.vendor, RpmScanVulnerability.product,
                  RpmScanVulnerability.id)
        .offset(offset).limit(page_size)
    ).all()
    return total, rows


def get_artifact_task(db: Session, task_id: int) -> RpmScanTask:
    """Read delivery metadata without loading scan results or large raw data."""
    task = db.scalar(
        select(RpmScanTask)
        .options(
            load_only(
                RpmScanTask.id,
                RpmScanTask.jenkins_job_full_name,
                RpmScanTask.jenkins_build_number,
                raiseload=True,
            ),
            selectinload(RpmScanTask.artifacts).load_only(
                RpmScanArtifact.id,
                RpmScanArtifact.task_id,
                RpmScanArtifact.name,
                RpmScanArtifact.artifact_type,
                RpmScanArtifact.relative_path,
                RpmScanArtifact.size_bytes,
                raiseload=True,
            ),
            raiseload("*"),
        )
        .where(RpmScanTask.id == task_id)
    )
    if task is None:
        raise HTTPException(status_code=404, detail="RPM scan task not found")
    return task


def _list_task_page(
    db: Session, search: str | None, state: str | None,
    page: int, page_size: int, fields: tuple[str, ...],
) -> tuple[int, list[RpmScanTask]]:
    filters = []
    if search:
        filters.append(RpmScanTask.rpm_name.ilike(f"%{search}%"))
    if state:
        filters.append(RpmScanTask.state == state.upper())
    total = db.scalar(select(func.count()).select_from(RpmScanTask).where(*filters)) or 0
    rows = db.scalars(
        select(RpmScanTask)
        .options(
            load_only(*(getattr(RpmScanTask, name) for name in fields), raiseload=True),
            raiseload("*"),
        )
        .where(*filters)
        .order_by(desc(RpmScanTask.created_at), desc(RpmScanTask.id))
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    return total, rows


def list_task_metadata_page(
    db: Session, search: str | None, state: str | None, page: int, page_size: int,
) -> tuple[int, list[RpmScanTask]]:
    return _list_task_page(db, search, state, page, page_size, TASK_PAYLOAD_FIELDS)


def list_task_web_page(
    db: Session, search: str | None, state: str | None, page: int, page_size: int,
) -> tuple[int, list[RpmScanTask]]:
    return _list_task_page(db, search, state, page, page_size, WEB_LIST_FIELDS)
