"""Drop the unused Jenkins build URL column from scan task tables."""

from alembic import op
import sqlalchemy as sa


revision = "0004_drop_jenkins_build_url"
down_revision = "0003_add_rpm_scans"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("rpm_scan_task", "jenkins_build_url")
    op.drop_column("srpm_scan_task", "jenkins_build_url")


def downgrade() -> None:
    op.add_column(
        "rpm_scan_task",
        sa.Column("jenkins_build_url", sa.Text(), nullable=True),
    )
    op.add_column(
        "srpm_scan_task",
        sa.Column("jenkins_build_url", sa.Text(), nullable=True),
    )
