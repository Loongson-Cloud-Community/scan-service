"""Task display formatting and public payloads; database reads live in task_queries."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..models import RpmScanTask


TASK_PAYLOAD_FIELDS = (
    "id",
    "scan_key",
    "jenkins_job_full_name",
    "jenkins_build_number",
    "rpm_name",
    "rpm_sha256",
    "state",
    "scanner",
    "scanner_version",
    "total_vulnerabilities",
    "component_count",
    "critical_count",
    "high_count",
    "medium_count",
    "low_count",
    "unknown_count",
    "created_at",
    "finished_at",
    "sync_status",
)


def format_timestamp(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "—"


def task_payload(task: RpmScanTask) -> dict[str, Any]:
    return {name: getattr(task, name) for name in TASK_PAYLOAD_FIELDS}
