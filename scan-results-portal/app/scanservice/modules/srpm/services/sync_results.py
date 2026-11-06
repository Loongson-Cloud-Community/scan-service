from __future__ import annotations

from typing import Any

from sqlalchemy import delete
from sqlalchemy.orm import Session

from ....scan_protocol import require_matching_identity
from ..models import SrpmScanFinding, SrpmScanSummary, SrpmScanTask
from ..schemas.manifest import SrpmManifest


def set_manifest(task: SrpmScanTask, manifest: dict[str, Any]) -> None:
    # A Jenkins build can contain both RPM and SRPM artifacts. Never treat an
    # RPM manifest as SRPM metadata even if it reaches this function.
    if str(manifest.get("scan_type") or "").lower() == "rpm":
        return

    # Validate the whole optional document before applying any of its fields.
    SrpmManifest.parse_obj(manifest)
    require_matching_identity({
        "jenkins_job_full_name": task.jenkins_job_full_name,
        "jenkins_build_number": task.jenkins_build_number,
        "srpm_name": task.srpm_name,
    }, manifest)

    for field in (
        "package_name",
        "version",
        "release",
        "nvr",
        "srpm_name",
        "architecture",
        "source_revision",
        "source_url",
        "source_sha256",
        "mock_config",
        "gate_result",
    ):
        value = manifest.get(field)
        if value is not None:
            setattr(task, field, value)

    scanner = manifest.get("scanner")
    scanner_name = None
    scanner_version = manifest.get("scanner_version")
    if isinstance(scanner, dict):
        scanner_name = scanner.get("name")
        scanner_version = scanner_version or scanner.get("version")
    else:
        scanner_name = scanner
    if scanner_name is not None:
        task.scanner = scanner_name
    if scanner_version is not None:
        task.scanner_version = scanner_version

    exit_code = manifest.get("csmock_exit_code")
    if isinstance(exit_code, int) and not isinstance(exit_code, bool):
        # Optional metadata cannot erase failure evidence from a callback.
        if task.csmock_exit_code is None or task.csmock_exit_code == 0:
            task.csmock_exit_code = exit_code

    plugins = manifest.get("plugins") or manifest.get("enabled_plugins")
    if isinstance(plugins, list) and all(isinstance(item, str) for item in plugins):
        task.enabled_plugins = plugins

    task.scan_metadata = {**(task.scan_metadata or {}), "manifest": manifest}


def set_ini(task: SrpmScanTask, metadata: dict[str, Any]) -> None:
    for source, target in (
        ("scanner", "scanner"),
        ("scanner_version", "scanner_version"),
        ("mock_config", "mock_config"),
    ):
        if metadata.get(source) and not getattr(task, target):
            setattr(task, target, metadata[source])
    if metadata.get("enabled_plugins") and not task.enabled_plugins:
        task.enabled_plugins = metadata["enabled_plugins"]
    task.scan_metadata = {**(task.scan_metadata or {}), "scan_ini": metadata.get("raw", {})}


def replace_results(
    session: Session,
    task: SrpmScanTask,
    summaries: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    session.execute(delete(SrpmScanSummary).where(SrpmScanSummary.task_id == task.id))
    session.execute(delete(SrpmScanFinding).where(SrpmScanFinding.task_id == task.id))
    for summary in summaries:
        session.add(
            SrpmScanSummary(
                task_id=task.id,
                checker=str(summary["checker"]),
                issue_type=str(summary["issue_type"]),
                count=int(summary["count"]),
            )
        )
    seen: set[str] = set()
    for finding in findings:
        fingerprint = str(finding["fingerprint"])
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        session.add(SrpmScanFinding(task_id=task.id, **finding))
