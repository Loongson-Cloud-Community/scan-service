"""Create initial Scan Results Portal schema."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None
json_type = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "scan_task",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("jenkins_job_full_name", sa.String(length=500), nullable=False),
        sa.Column("jenkins_build_number", sa.Integer(), nullable=False),
        sa.Column("jenkins_build_url", sa.Text(), nullable=True),
        sa.Column("package_name", sa.String(length=200), nullable=True),
        sa.Column("version", sa.String(length=200), nullable=True),
        sa.Column("release", sa.String(length=200), nullable=True),
        sa.Column("nvr", sa.String(length=500), nullable=True),
        sa.Column("srpm_name", sa.String(length=500), nullable=True),
        sa.Column("architecture", sa.String(length=100), nullable=True),
        sa.Column("source_revision", sa.String(length=500), nullable=True),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("source_sha256", sa.String(length=128), nullable=True),
        sa.Column("lifecycle_state", sa.String(length=30), nullable=False),
        sa.Column("execution_result", sa.String(length=30), nullable=True),
        sa.Column("scan_result", sa.String(length=30), nullable=False),
        sa.Column("gate_result", sa.String(length=30), nullable=False),
        sa.Column("jenkins_node", sa.String(length=200), nullable=True),
        sa.Column("triggered_by", sa.String(length=200), nullable=True),
        sa.Column("scanner", sa.String(length=100), nullable=True),
        sa.Column("scanner_version", sa.String(length=100), nullable=True),
        sa.Column("mock_config", sa.String(length=300), nullable=True),
        sa.Column("enabled_plugins", json_type, nullable=True),
        sa.Column("csmock_exit_code", sa.Integer(), nullable=True),
        sa.Column("total_findings", sa.Integer(), nullable=True),
        sa.Column("scan_metadata", json_type, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("queued_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_ms", sa.BigInteger(), nullable=True),
        sa.Column("scan_duration_ms", sa.BigInteger(), nullable=True),
        sa.Column("last_synced_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sync_status", sa.String(length=30), nullable=False),
        sa.Column("sync_error", sa.Text(), nullable=True),
        sa.Column("created_at_service", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at_service", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "jenkins_job_full_name",
            "jenkins_build_number",
            name="uq_scan_task_jenkins_build",
        ),
    )
    op.create_index("ix_scan_task_created_at", "scan_task", ["created_at"])
    op.create_index("ix_scan_task_package_name", "scan_task", ["package_name"])
    op.create_index("ix_scan_task_lifecycle_state", "scan_task", ["lifecycle_state"])
    op.create_index("ix_scan_task_scan_result", "scan_task", ["scan_result"])

    op.create_table(
        "scan_artifact",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=500), nullable=False),
        sa.Column("artifact_type", sa.String(length=50), nullable=False),
        sa.Column("relative_path", sa.Text(), nullable=False),
        sa.Column("jenkins_url", sa.Text(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("sha256", sa.String(length=128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["scan_task.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id", "relative_path", name="uq_scan_artifact_path"),
    )

    op.create_table(
        "scan_summary",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("checker", sa.String(length=200), nullable=False),
        sa.Column("issue_type", sa.String(length=500), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["scan_task.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id", "checker", "issue_type", name="uq_scan_summary_issue"),
    )

    op.create_table(
        "scan_finding",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_id", sa.Integer(), nullable=False),
        sa.Column("fingerprint", sa.String(length=500), nullable=False),
        sa.Column("checker", sa.String(length=200), nullable=True),
        sa.Column("rule_id", sa.String(length=500), nullable=True),
        sa.Column("severity", sa.String(length=50), nullable=True),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("line", sa.Integer(), nullable=True),
        sa.Column("column", sa.Integer(), nullable=True),
        sa.Column("code_context", sa.Text(), nullable=True),
        sa.Column("raw", json_type, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["task_id"], ["scan_task.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("task_id", "fingerprint", name="uq_scan_finding_fingerprint"),
    )
    op.create_index("ix_scan_finding_task_id", "scan_finding", ["task_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_finding_task_id", table_name="scan_finding")
    op.drop_table("scan_finding")
    op.drop_table("scan_summary")
    op.drop_table("scan_artifact")
    op.drop_index("ix_scan_task_scan_result", table_name="scan_task")
    op.drop_index("ix_scan_task_lifecycle_state", table_name="scan_task")
    op.drop_index("ix_scan_task_package_name", table_name="scan_task")
    op.drop_index("ix_scan_task_created_at", table_name="scan_task")
    op.drop_table("scan_task")
