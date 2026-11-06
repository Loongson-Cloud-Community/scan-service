"""Task display formatting and public payloads; database reads live in task_queries."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..models import SrpmScanTask


TASK_PAYLOAD_FIELDS = (
    "id",
    "jenkins_job_full_name",
    "jenkins_build_number",
    "package_name",
    "version",
    "release",
    "nvr",
    "srpm_name",
    "architecture",
    "lifecycle_state",
    "execution_result",
    "scan_result",
    "gate_result",
    "jenkins_node",
    "triggered_by",
    "scanner",
    "scanner_version",
    "mock_config",
    "enabled_plugins",
    "total_findings",
    "created_at",
    "started_at",
    "finished_at",
    "duration_ms",
    "scan_duration_ms",
    "last_synced_at",
    "sync_status",
)


def format_timestamp(value: datetime | None) -> str:
    if value is None:
        return "—"
    return value.strftime("%Y-%m-%d %H:%M:%S")


def scan_method(task: SrpmScanTask) -> str:
    metadata = task.scan_metadata or {}
    manifest = metadata.get("manifest") or {}
    scan_ini = metadata.get("scan_ini") or {}
    return manifest.get("method") or scan_ini.get("method") or "csmock"


def detail_values(task: SrpmScanTask) -> dict[str, Any]:
    metadata = task.scan_metadata or {}
    manifest = metadata.get("manifest") or {}
    scan_ini = metadata.get("scan_ini") or {}
    srpm_name = (
        task.srpm_name
        or manifest.get("srpm_name")
        or (f"{task.nvr}.src.rpm" if task.nvr else None)
    )
    csmock_args = (
        manifest.get("csmock_args")
        or scan_ini.get("csmock_args")
        or scan_ini.get("tool-args")
        or scan_ini.get("tool_args")
    )
    args = manifest.get("args") or scan_ini.get("args")
    args_fields: list[dict[str, str]] = []
    if args:
        args_fields.append({"name": "", "value": str(args)})
    if not args:
        if task.enabled_plugins:
            args_fields.append(
                {"name": "analyzers", "value": f'"{",".join(task.enabled_plugins)}"'}
            )
        if csmock_args:
            args_fields.append({"name": "csmock_args", "value": f'"{csmock_args}"'})
        if task.mock_config:
            args_fields.append({"name": "mock_config", "value": f'"{task.mock_config}"'})
        if srpm_name:
            args_fields.append({"name": "srpm_name", "value": f'"{srpm_name}"'})
    elif csmock_args:
        args_fields.append({"name": "csmock_args", "value": f'"{csmock_args}"'})
    return {"method": scan_method(task), "args": args_fields, "srpm_name": srpm_name}


def task_payload(task: SrpmScanTask) -> dict[str, Any]:
    return {name: getattr(task, name) for name in TASK_PAYLOAD_FIELDS}
