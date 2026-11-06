"""Public RPM payloads; database reads live in task_queries."""

from __future__ import annotations

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


def task_payload(task: RpmScanTask) -> dict[str, Any]:
    return {name: getattr(task, name) for name in TASK_PAYLOAD_FIELDS}
