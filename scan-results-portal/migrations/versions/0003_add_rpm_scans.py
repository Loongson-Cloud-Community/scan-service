"""Add RPM vulnerability scan tables."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0003_add_rpm_scans"
down_revision = "0002_name_srpm_tables"
branch_labels = None
depends_on = None
json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "rpm_scan_task",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_key", sa.String(length=128), nullable=False),
        sa.Column("jenkins_job_full_name", sa.String(length=500), nullable=False),
        sa.Column("jenkins_build_number", sa.Integer(), nullable=False),
        sa.Column("jenkins_build_url", sa.Text(), nullable=True),
        sa.Column("rpm_name", sa.String(length=500), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=True),
        sa.Column("epoch", sa.String(length=50), nullable=True),
        sa.Column("version", sa.String(length=200), nullable=True),
        sa.Column("release", sa.String(length=200), nullable=True),
        sa.Column("architecture", sa.String(length=100), nullable=True),
        sa.Column("source_rpm", sa.String(length=500), nullable=True),
        sa.Column("rpm_sha256", sa.String(length=64), nullable=False),
        sa.Column("rpm_size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("state", sa.String(length=30), nullable=False),
        sa.Column("scanner", sa.String(length=100), nullable=True),
        sa.Column("scanner_version", sa.String(length=100), nullable=True),
        sa.Column("cbt_exit_code", sa.Integer(), nullable=True),
        sa.Column("scanner_args", json_type, nullable=True),
        sa.Column("triggered_by", sa.String(length=200), nullable=True),
        sa.Column("total_vulnerabilities", sa.Integer(), nullable=True),
        sa.Column("component_count", sa.Integer(), nullable=True),
        sa.Column("critical_count", sa.Integer(), nullable=False),
        sa.Column("high_count", sa.Integer(), nullable=False),
        sa.Column("medium_count", sa.Integer(), nullable=False),
        sa.Column("low_count", sa.Integer(), nullable=False),
        sa.Column("unknown_count", sa.Integer(), nullable=False),
        sa.Column("scan_metadata", json_type, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sync_status", sa.String(length=30), nullable=False),
        sa.Column("sync_error", sa.Text(), nullable=True),
        sa.Column("created_at_service", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at_service", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "jenkins_job_full_name",
            "jenkins_build_number",
            "scan_key",
            name="uq_rpm_scan_task_jenkins_build_key",
        ),
    )
    op.create_index("ix_rpm_scan_task_created_at", "rpm_scan_task", ["created_at"])
    op.create_index("ix_rpm_scan_task_state", "rpm_scan_task", ["state"])
    op.create_index("ix_rpm_scan_task_rpm_name", "rpm_scan_task", ["rpm_name"])

    op.create_table(
        "rpm_scan_artifact",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("artifact_type", sa.String(length=50), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("jenkins_url", sa.Text(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["rpm_scan_task.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id", "relative_path", name="uq_rpm_scan_artifact_path"),
    )
    op.create_table(
        "rpm_scan_component",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("vendor", sa.String(length=200), nullable=False),
        sa.Column("product", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=200), nullable=False),
        sa.Column("vulnerability_count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["rpm_scan_task.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id", "vendor", "product", "version", name="uq_rpm_scan_component"),
    )
    op.create_table(
        "rpm_scan_vulnerability",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("vendor", sa.String(length=200), nullable=False),
        sa.Column("product", sa.String(length=200), nullable=False),
        sa.Column("version", sa.String(length=200), nullable=False),
        sa.Column("cve_number", sa.String(length=50), nullable=False),
        sa.Column("severity", sa.String(length=30), nullable=False),
        sa.Column("score", sa.Float(), nullable=True),
        sa.Column("source", sa.String(length=100), nullable=True),
        sa.Column("cvss_version", sa.String(length=30), nullable=True),
        sa.Column("cvss_vector", sa.Text(), nullable=True),
        sa.Column("paths", sa.Text(), nullable=True),
        sa.Column("remarks", sa.String(length=100), nullable=True),
        sa.Column("comments", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("raw", json_type, nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["rpm_scan_task.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id", "fingerprint", name="uq_rpm_scan_vulnerability"),
    )
    op.create_index("ix_rpm_scan_vulnerability_task_id", "rpm_scan_vulnerability", ["task_id"])
    op.create_index("ix_rpm_scan_vulnerability_cve", "rpm_scan_vulnerability", ["cve_number"])


def downgrade() -> None:
    op.drop_index("ix_rpm_scan_vulnerability_cve", table_name="rpm_scan_vulnerability")
    op.drop_index("ix_rpm_scan_vulnerability_task_id", table_name="rpm_scan_vulnerability")
    op.drop_table("rpm_scan_vulnerability")
    op.drop_table("rpm_scan_component")
    op.drop_table("rpm_scan_artifact")
    op.drop_index("ix_rpm_scan_task_rpm_name", table_name="rpm_scan_task")
    op.drop_index("ix_rpm_scan_task_state", table_name="rpm_scan_task")
    op.drop_index("ix_rpm_scan_task_created_at", table_name="rpm_scan_task")
    op.drop_table("rpm_scan_task")
