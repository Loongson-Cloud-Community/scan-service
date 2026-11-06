from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
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


class RpmScanTask(Base):
    __tablename__ = "rpm_scan_task"
    __table_args__ = (
        UniqueConstraint(
            "jenkins_job_full_name",
            "jenkins_build_number",
            "scan_key",
            name="uq_rpm_scan_task_jenkins_build_key",
        ),
        Index("ix_rpm_scan_task_created_at", "created_at"),
        Index("ix_rpm_scan_task_state", "state"),
        Index("ix_rpm_scan_task_rpm_name", "rpm_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_key: Mapped[str] = mapped_column(String(128), nullable=False)
    jenkins_job_full_name: Mapped[str] = mapped_column(String(500), nullable=False)
    jenkins_build_number: Mapped[int] = mapped_column(Integer, nullable=False)

    rpm_name: Mapped[str] = mapped_column(String(500), nullable=False)
    name: Mapped[str | None] = mapped_column(String(200))
    epoch: Mapped[str | None] = mapped_column(String(50))
    version: Mapped[str | None] = mapped_column(String(200))
    release: Mapped[str | None] = mapped_column(String(200))
    architecture: Mapped[str | None] = mapped_column(String(100))
    source_rpm: Mapped[str | None] = mapped_column(String(500))
    rpm_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    rpm_size_bytes: Mapped[int | None] = mapped_column(BigInteger)

    state: Mapped[str] = mapped_column(String(30), nullable=False)
    scanner: Mapped[str | None] = mapped_column(String(100))
    scanner_version: Mapped[str | None] = mapped_column(String(100))
    cbt_exit_code: Mapped[int | None] = mapped_column(Integer)
    scanner_args: Mapped[list[str] | None] = mapped_column(JSON_TYPE)
    triggered_by: Mapped[str | None] = mapped_column(String(200))

    total_vulnerabilities: Mapped[int | None] = mapped_column(Integer)
    component_count: Mapped[int | None] = mapped_column(Integer)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    unknown_count: Mapped[int] = mapped_column(Integer, default=0)
    scan_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSON_TYPE)

    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_synced_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sync_status: Mapped[str] = mapped_column(String(30), default="PENDING")
    sync_error: Mapped[str | None] = mapped_column(Text)
    created_at_service: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at_service: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    artifacts: Mapped[list["RpmScanArtifact"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    components: Mapped[list["RpmScanComponent"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[list["RpmScanVulnerability"]] = relationship(
        back_populates="task", cascade="all, delete-orphan"
    )


class RpmScanArtifact(Base):
    __tablename__ = "rpm_scan_artifact"
    __table_args__ = (
        UniqueConstraint("task_id", "relative_path", name="uq_rpm_scan_artifact_path"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("rpm_scan_task.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(50), nullable=False)
    relative_path: Mapped[str] = mapped_column(Text, nullable=False)
    jenkins_url: Mapped[str | None] = mapped_column(Text)
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    task: Mapped[RpmScanTask] = relationship(back_populates="artifacts")


class RpmScanComponent(Base):
    __tablename__ = "rpm_scan_component"
    __table_args__ = (
        UniqueConstraint(
            "task_id", "vendor", "product", "version", name="uq_rpm_scan_component"
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("rpm_scan_task.id", ondelete="CASCADE"), nullable=False
    )
    vendor: Mapped[str] = mapped_column(String(200), nullable=False)
    product: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(200), nullable=False)
    vulnerability_count: Mapped[int] = mapped_column(Integer, nullable=False)

    task: Mapped[RpmScanTask] = relationship(back_populates="components")


class RpmScanVulnerability(Base):
    __tablename__ = "rpm_scan_vulnerability"
    __table_args__ = (
        UniqueConstraint("task_id", "fingerprint", name="uq_rpm_scan_vulnerability"),
        Index("ix_rpm_scan_vulnerability_task_id", "task_id"),
        Index("ix_rpm_scan_vulnerability_cve", "cve_number"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_id: Mapped[int] = mapped_column(
        ForeignKey("rpm_scan_task.id", ondelete="CASCADE"), nullable=False
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    vendor: Mapped[str] = mapped_column(String(200), nullable=False)
    product: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str] = mapped_column(String(200), nullable=False)
    cve_number: Mapped[str] = mapped_column(String(50), nullable=False)
    severity: Mapped[str] = mapped_column(String(30), nullable=False)
    score: Mapped[float | None] = mapped_column(Float)
    source: Mapped[str | None] = mapped_column(String(100))
    cvss_version: Mapped[str | None] = mapped_column(String(30))
    cvss_vector: Mapped[str | None] = mapped_column(Text)
    paths: Mapped[str | None] = mapped_column(Text)
    remarks: Mapped[str | None] = mapped_column(String(100))
    comments: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)

    task: Mapped[RpmScanTask] = relationship(back_populates="vulnerabilities")
