from __future__ import annotations

"""SRPM persistence models."""

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ...db import Base


JSON_TYPE = JSON().with_variant(JSONB(), "postgresql")


class SrpmScanTask(Base):
    __tablename__ = "srpm_scan_task"
    __table_args__ = (
        UniqueConstraint(
            "jenkins_job_full_name",
            "jenkins_build_number",
            name="uq_srpm_scan_task_jenkins_build",
        ),
        Index("ix_srpm_scan_task_created_at", "created_at"),
        Index("ix_srpm_scan_task_package_name", "package_name"),
        Index("ix_srpm_scan_task_lifecycle_state", "lifecycle_state"),
        Index("ix_srpm_scan_task_scan_result", "scan_result"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    jenkins_job_full_name: Mapped[str] = mapped_column(String(500), nullable=False)
    jenkins_build_number: Mapped[int] = mapped_column(Integer, nullable=False)

    package_name: Mapped[str | None] = mapped_column(String(200))
    version: Mapped[str | None] = mapped_column(String(200))
    release: Mapped[str | None] = mapped_column(String(200))
    nvr: Mapped[str | None] = mapped_column(String(500))
    srpm_name: Mapped[str | None] = mapped_column(String(500))
    architecture: Mapped[str | None] = mapped_column(String(100))
    source_revision: Mapped[str | None] = mapped_column(String(500))
    source_url: Mapped[str | None] = mapped_column(Text)
    source_sha256: Mapped[str | None] = mapped_column(String(128))

    lifecycle_state: Mapped[str] = mapped_column(String(30), default="DISCOVERED")
    execution_result: Mapped[str | None] = mapped_column(String(30))
    scan_result: Mapped[str] = mapped_column(String(30), default="NOT_AVAILABLE")
    gate_result: Mapped[str] = mapped_column(String(30), default="NOT_EVALUATED")

    jenkins_node: Mapped[str | None] = mapped_column(String(200))
    triggered_by: Mapped[str | None] = mapped_column(String(200))
    scanner: Mapped[str | None] = mapped_column(String(100))
    scanner_version: Mapped[str | None] = mapped_column(String(100))
    mock_config: Mapped[str | None] = mapped_column(String(300))
    enabled_plugins: Mapped[list[str] | None] = mapped_column(JSON_TYPE)
    csmock_exit_code: Mapped[int | None] = mapped_column(Integer)

    total_findings: Mapped[int | None] = mapped_column(Integer)
    scan_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON_TYPE)

    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    queued_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scan_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    scan_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(BigInteger)
    scan_duration_ms: Mapped[int | None] = mapped_column(BigInteger)

    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sync_status: Mapped[str] = mapped_column(String(30), default="PENDING")
    sync_error: Mapped[str | None] = mapped_column(Text)
    created_at_service: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at_service: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    artifacts: Mapped[list["SrpmScanArtifact"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    summaries: Mapped[list["SrpmScanSummary"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    findings: Mapped[list["SrpmScanFinding"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )


class SrpmScanArtifact(Base):
    __tablename__ = "srpm_scan_artifact"
    __table_args__ = (
        UniqueConstraint(
            "task_id", "relative_path", name="uq_srpm_scan_artifact_path"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("srpm_scan_task.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(50), nullable=False)
    relative_path: Mapped[str] = mapped_column(Text, nullable=False)
    jenkins_url: Mapped[str | None] = mapped_column(Text)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    sha256: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    task: Mapped[SrpmScanTask] = relationship(back_populates="artifacts")


class SrpmScanSummary(Base):
    __tablename__ = "srpm_scan_summary"
    __table_args__ = (
        UniqueConstraint(
            "task_id", "checker", "issue_type", name="uq_srpm_scan_summary_issue"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("srpm_scan_task.id", ondelete="CASCADE"), nullable=False
    )
    checker: Mapped[str] = mapped_column(String(200), nullable=False)
    issue_type: Mapped[str] = mapped_column(String(500), nullable=False)
    count: Mapped[int] = mapped_column(Integer, nullable=False)

    task: Mapped[SrpmScanTask] = relationship(back_populates="summaries")


class SrpmScanFinding(Base):
    __tablename__ = "srpm_scan_finding"
    __table_args__ = (
        UniqueConstraint(
            "task_id", "fingerprint", name="uq_srpm_scan_finding_fingerprint"
        ),
        Index("ix_srpm_scan_finding_task_id", "task_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("srpm_scan_task.id", ondelete="CASCADE"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(500), nullable=False)
    checker: Mapped[str | None] = mapped_column(String(200))
    rule_id: Mapped[str | None] = mapped_column(String(500))
    severity: Mapped[str | None] = mapped_column(String(50))
    message: Mapped[str | None] = mapped_column(Text)
    file_path: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer)
    column: Mapped[int | None] = mapped_column(Integer)
    code_context: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSON_TYPE)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    task: Mapped[SrpmScanTask] = relationship(back_populates="findings")
