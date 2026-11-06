from __future__ import annotations

from datetime import datetime, timezone
import configparser
import json
import tarfile
from typing import Any

from sqlalchemy.orm import Session

from ..csmock.archive import (
    ArchiveMember,
    list_visible_members,
    read_visible_member,
)
from ..csmock.acceptance import validated_exit_code
from ....config import Settings
from ....jenkins import JenkinsClient
from ....resync import resync_registered_tasks
from ....scan_state import FAILED, FINISHED, NOT_AVAILABLE, RUNNING, is_terminal, state_without_results
from ....task_writes import ensure_locked_task
from ..models import SrpmScanTask
from ..parsers.csmock import (
    parse_sarif,
    parse_nvr_from_path,
    parse_scan_ini,
    parse_summary,
    summarize_findings,
)
from .sync_artifacts import (
    REQUIRED_SCAN_FILES,
    artifact_url as _artifact_url,
    find_artifact as _find_artifact,
    find_valid_scan_archive as _find_valid_scan_archive,
    is_archive as _is_archive,
    is_srpm_artifact as _is_srpm_artifact,
    upsert_archive_members as _upsert_archive_members,
    upsert_artifact as _upsert_artifact,
)
from .sync_results import (
    replace_results as _replace_results,
    set_ini as _set_ini,
    set_manifest as _set_manifest,
)

def _jenkins_time(milliseconds: Any) -> datetime | None:
    if not milliseconds:
        return None
    return datetime.fromtimestamp(float(milliseconds) / 1000, tz=timezone.utc)


def _cause_user(build: dict[str, Any]) -> str | None:
    for action in build.get("actions") or []:
        for cause in action.get("causes") or []:
            return cause.get("userName") or cause.get("userId") or cause.get(
                "shortDescription"
            )
    return None


def _sync_build(
    session: Session,
    client: JenkinsClient,
    settings: Settings,
    build_number: int,
    job: str | None = None,
) -> SrpmScanTask:
    number = int(build_number)
    limits = settings.artifact_limits
    job = job or ""
    if not job:
        raise ValueError("Jenkins job is required to synchronize a build")
    task = ensure_locked_task(session, SrpmScanTask, {
        "jenkins_job_full_name": job, "jenkins_build_number": number,
    }, {
        "lifecycle_state": "DISCOVERED", "scan_result": NOT_AVAILABLE,
        "gate_result": "NOT_EVALUATED", "sync_status": "PENDING",
    })

    if is_terminal(task.scan_result):
        return task

    detail = client.get_build(job, number)
    building = bool(detail.get("building"))
    task.lifecycle_state = "RUNNING" if building else "COMPLETED"
    task.execution_result = detail.get("result")
    if task.created_at is None:
        task.created_at = _jenkins_time(detail.get("timestamp"))
    if task.started_at is None:
        task.started_at = task.created_at
    task.triggered_by = _cause_user(detail)

    for row in list(task.artifacts):
        if not _is_srpm_artifact(row.relative_path):
            session.delete(row)

    artifacts = [
        artifact
        for artifact in detail.get("artifacts") or []
        if _is_srpm_artifact(
            str(artifact.get("relativePath") or artifact.get("fileName") or "")
        )
    ]
    for artifact in artifacts:
        _upsert_artifact(session, task, artifact, client, job, number)
    session.flush()

    top_level_names = {
        str(artifact.get("fileName") or path.rsplit("/", 1)[-1])
        for artifact in artifacts
        for path in [artifact.get("relativePath") or artifact.get("fileName") or ""]
        if path
    }
    archive_contents: list[tuple[str, bytes, list[ArchiveMember]]] = []
    for artifact in artifacts:
        archive_path = artifact.get("relativePath") or artifact.get("fileName") or ""
        size = artifact.get("size")
        if not archive_path or not _is_archive(archive_path):
            continue
        if size is not None and int(size) > limits.max_archive_bytes:
            continue
        try:
            content = client.get_artifact(
                job,
                number,
                archive_path,
                max_bytes=limits.max_archive_bytes,
            )
            members = list_visible_members(content, limits)
        except (OSError, tarfile.TarError, ValueError):
            continue
        archive_contents.append((archive_path, content, members))
        _upsert_archive_members(session, task, archive_path, members, top_level_names)
    valid_scan_archive = _find_valid_scan_archive(archive_contents)

    artifact_paths = [
        artifact.get("relativePath") or artifact.get("fileName") or ""
        for artifact in artifacts
    ]
    inferred_nvr = next(
        (parsed for parsed in map(parse_nvr_from_path, artifact_paths) if parsed),
        None,
    )
    if inferred_nvr:
        for field, value in inferred_nvr.items():
            if not getattr(task, field):
                setattr(task, field, value)
        if not task.srpm_name and task.nvr:
            task.srpm_name = f"{task.nvr}.src.rpm"

    def read_artifact(basename: str) -> bytes | None:
        artifact = _find_artifact(artifacts, basename)
        if not artifact:
            return None
        size = artifact.get("size")
        if size is not None and int(size) > limits.max_parse_bytes:
            return None
        path = artifact.get("relativePath") or artifact.get("fileName")
        if not path:
            return None
        return client.get_artifact(
            job,
            number,
            path,
            max_bytes=limits.max_parse_bytes,
        )

    def read_archive_artifact(basename: str) -> bytes | None:
        archives = [valid_scan_archive] if valid_scan_archive else archive_contents
        for archive in archives:
            if archive is None:
                continue
            _, content, members = archive
            member = next((item for item in members if item.name == basename), None)
            if member is None:
                continue
            if member.size > limits.max_parse_bytes:
                continue
            try:
                return read_visible_member(content, member.path, limits)
            except (KeyError, OSError, tarfile.TarError):
                continue
        return None

    def read_result_artifact(basename: str) -> bytes | None:
        archive_result = read_archive_artifact(basename)
        if archive_result is not None:
            return archive_result
        return read_artifact(basename)

    manifest_bytes = read_result_artifact("scan-manifest.json")
    metadata = dict(task.scan_metadata or {})
    metadata.pop("manifest_error", None)
    task.scan_metadata = metadata
    if manifest_bytes is not None:
        try:
            manifest = json.loads(manifest_bytes.decode("utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("scan-manifest.json must contain an object")
            _set_manifest(task, manifest)
        except (UnicodeDecodeError, ValueError) as exc:
            task.scan_metadata = {
                **(task.scan_metadata or {}), "manifest_error": str(exc)[:4000],
            }

    # A direct file must not replace invalid or oversized required archive data.
    read_required = read_archive_artifact if valid_scan_archive else read_result_artifact
    ini_bytes = read_required("scan.ini")
    ini_valid = False
    result_error = "A single csmock archive with all required result files is unavailable"
    if ini_bytes:
        try:
            ini_metadata = parse_scan_ini(ini_bytes.decode("utf-8"))
            exit_code = validated_exit_code(
                ini_metadata, task.csmock_exit_code, srpm_name=task.srpm_name,
            )
            _set_ini(task, ini_metadata)
            task.csmock_exit_code = exit_code
            ini_valid = True
        except (UnicodeDecodeError, ValueError, configparser.Error) as exc:
            result_error = str(exc)
    elif valid_scan_archive:
        result_error = "scan.ini is empty or exceeds the parsing limit"

    summary_rows: list[dict[str, Any]] = []
    summary_bytes = read_required("scan-results-summary.txt")
    summary_valid = False
    if summary_bytes is not None:
        try:
            summary_rows = parse_summary(summary_bytes.decode("utf-8"))
            summary_valid = True
        except (UnicodeDecodeError, ValueError) as exc:
            result_error = str(exc)
    elif valid_scan_archive:
        result_error = "scan-results-summary.txt exceeds the parsing limit or is unreadable"

    findings: list[dict[str, Any]] = []
    sarif_artifact = next(
        (
            artifact
            for artifact in artifacts
            if str(artifact.get("relativePath") or artifact.get("fileName") or "").lower().endswith(".sarif")
        ),
        None,
    )
    sarif_bytes = None
    if sarif_artifact:
        path = sarif_artifact.get("relativePath") or sarif_artifact.get("fileName")
        size = sarif_artifact.get("size")
        if size is None or int(size) <= limits.max_parse_bytes:
            sarif_bytes = client.get_artifact(
                job,
                number,
                path,
                max_bytes=limits.max_parse_bytes,
            )
    else:
        for _, content, members in archive_contents:
            member = next((item for item in members if item.name.lower().endswith(".sarif")), None)
            if member is not None and member.size <= limits.max_parse_bytes:
                try:
                    sarif_bytes = read_visible_member(content, member.path, limits)
                except (KeyError, OSError, tarfile.TarError):
                    sarif_bytes = None
                break
    if sarif_bytes:
        parsed = parse_sarif(sarif_bytes.decode("utf-8", errors="replace"))
        findings = parsed["findings"]
        task.scanner = task.scanner or parsed.get("scanner")
        task.scanner_version = task.scanner_version or parsed.get("scanner_version")
        if not summary_rows:
            summary_rows = summarize_findings(findings)

    has_valid_result = (
        valid_scan_archive is not None
        and ini_valid
        and summary_valid
        and task.csmock_exit_code == 0
    )
    if has_valid_result or findings:
        _replace_results(session, task, summary_rows, findings)
        task.total_findings = len(findings) if findings else sum(
            int(row["count"]) for row in summary_rows
        )

    if task.csmock_exit_code is not None and task.csmock_exit_code != 0:
        task.scan_result = FAILED
    elif has_valid_result:
        task.scan_result = FINISHED
    else:
        task.scan_result = state_without_results(
            building=building,
            ended=task.scan_finished_at is not None or task.finished_at is not None,
        )

    now = datetime.now(timezone.utc)
    task.last_synced_at = now
    task.sync_status = (
        "ERROR" if task.scan_result == NOT_AVAILABLE
        else "PENDING" if task.scan_result == RUNNING else "SYNCED"
    )
    task.sync_error = result_error[:4000] if task.scan_result == NOT_AVAILABLE else None
    return task


def sync_build(
    session: Session,
    client: JenkinsClient,
    settings: Settings,
    build_number: int,
    job_full_name: str | None = None,
) -> SrpmScanTask:
    """Synchronize one SRPM build using its explicit Jenkins Job identity."""
    return _sync_build(session, client, settings, build_number, job=job_full_name)


def _resync_task(
    session: Session,
    client: JenkinsClient,
    settings: Settings,
    task: SrpmScanTask,
) -> SrpmScanTask:
    return _sync_build(
        session,
        client,
        settings,
        task.jenkins_build_number,
        job=task.jenkins_job_full_name,
    )


def sync_registered_tasks(settings: Settings, session: Session) -> dict[str, int]:
    """Re-sync registered SRPM tasks that have not reached a terminal state."""
    return resync_registered_tasks(
        settings,
        session,
        model=SrpmScanTask,
        state_column=SrpmScanTask.scan_result,
        active_states=(RUNNING, NOT_AVAILABLE),
        sync_one=_resync_task,
    )
