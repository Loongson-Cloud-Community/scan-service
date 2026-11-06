"""Name the existing tables explicitly for SRPM scans."""

from alembic import op


revision = "0002_name_srpm_tables"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.rename_table("scan_task", "srpm_scan_task")
    op.rename_table("scan_artifact", "srpm_scan_artifact")
    op.rename_table("scan_summary", "srpm_scan_summary")
    op.rename_table("scan_finding", "srpm_scan_finding")


def downgrade() -> None:
    op.rename_table("srpm_scan_finding", "scan_finding")
    op.rename_table("srpm_scan_summary", "scan_summary")
    op.rename_table("srpm_scan_artifact", "scan_artifact")
    op.rename_table("srpm_scan_task", "scan_task")
