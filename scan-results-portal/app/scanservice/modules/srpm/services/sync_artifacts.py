from __future__ import annotations

import tarfile
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..csmock.archive import ArchiveMember, list_visible_members
from ....jenkins import JenkinsClient
from ..models import SrpmScanArtifact, SrpmScanTask
from ..parsers.csmock import classify_artifact


SRPM_ARTIFACT_PREFIX = "srpm-scan-artifacts/"
REQUIRED_SCAN_FILES = frozenset(
    {
        "scan.ini",
        "scan-results-summary.txt",
        "scan-results.js",
        "scan-results.err",
        "scan-results.html",
        "scan.log",
    }
)


def is_srpm_artifact(path: str) -> bool:
    return path.startswith(SRPM_ARTIFACT_PREFIX)


def find_artifact(
    artifacts: list[dict[str, object]], basename: str
) -> dict[str, object] | None:
    for artifact in artifacts:
        path = artifact.get("relativePath") or artifact.get("fileName") or ""
        path = str(path)
        if not is_srpm_artifact(path):
            continue
        if path == basename or path.endswith(f"/{basename}"):
            return artifact
    return None


def artifact_url(
    client: JenkinsClient,
    artifact: dict[str, object],
    job: str,
    number: int,
) -> str:
    url = artifact.get("url")
    if url:
        return str(url) if str(url).startswith("http") else client._url(str(url))
    path = artifact.get("relativePath") or artifact.get("fileName") or ""
    escaped = "/".join(quote(str(part), safe="") for part in str(path).split("/"))
    return client._url(f"{client._job_path(job)}/{number}/artifact/{escaped}")


def upsert_artifact(
    session: Session,
    task: SrpmScanTask,
    artifact: dict[str, object],
    client: JenkinsClient,
    job: str,
    number: int,
) -> None:
    relative_path = artifact.get("relativePath") or artifact.get("fileName") or ""
    if not relative_path:
        return
    relative_path = str(relative_path)
    if not is_srpm_artifact(relative_path):
        return
    row = session.scalar(
        select(SrpmScanArtifact).where(
            SrpmScanArtifact.task_id == task.id,
            SrpmScanArtifact.relative_path == relative_path,
        )
    )
    if row is None:
        row = SrpmScanArtifact(
            task_id=task.id,
            relative_path=relative_path,
            name=str(artifact.get("fileName") or relative_path),
        )
        session.add(row)
    row.name = str(artifact.get("fileName") or relative_path.rsplit("/", 1)[-1])
    row.artifact_type = classify_artifact(relative_path)
    row.jenkins_url = artifact_url(client, artifact, job, number)
    row.size_bytes = artifact.get("size")


def is_archive(path: str) -> bool:
    return path.lower().endswith(
        (".tar", ".tar.xz", ".tar.gz", ".tar.bz2", ".tgz", ".tbz2", ".zip")
    )


def find_valid_scan_archive(
    archives: list[tuple[str, bytes, list[ArchiveMember]]]
) -> tuple[str, bytes, list[ArchiveMember]] | None:
    for archive in archives:
        path, _, members = archive
        if not is_srpm_artifact(path):
            continue
        if not path.lower().endswith(".tar.xz"):
            continue
        required = [member for member in members if member.name in REQUIRED_SCAN_FILES]
        # Required files must describe one result, not a mixture of roots or
        # ambiguous duplicate entries. Flat and NVR-prefixed archives are valid.
        if (
            len(required) == len(REQUIRED_SCAN_FILES)
            and {member.name for member in required} == REQUIRED_SCAN_FILES
            and len({member.path.rpartition("/")[0] for member in required}) == 1
        ):
            return archive
    return None


def upsert_archive_members(
    session: Session,
    task: SrpmScanTask,
    archive_path: str,
    members: list[ArchiveMember],
    top_level_names: set[str],
) -> None:
    if not is_srpm_artifact(archive_path):
        return
    prefix = f"{archive_path}::"
    old_rows = session.scalars(
        select(SrpmScanArtifact).where(SrpmScanArtifact.task_id == task.id)
    ).all()
    existing = {
        row.relative_path: row
        for row in old_rows
        if row.relative_path.startswith(prefix)
    }
    current_paths: set[str] = set()

    for member in members:
        # If Jenkins also archived the individual file, keep the direct
        # artifact as the canonical link and avoid a duplicate display row.
        if member.name in top_level_names:
            continue
        relative_path = f"{prefix}{member.path}"
        current_paths.add(relative_path)
        row = existing.get(relative_path)
        if row is None:
            row = SrpmScanArtifact(task_id=task.id, relative_path=relative_path)
            session.add(row)
        row.name = member.name
        row.artifact_type = classify_artifact(member.name)
        row.jenkins_url = (
            f"/api/v1/srpm/tasks/{task.id}/archive/"
            f"{quote(relative_path, safe='')}"
        )
        row.size_bytes = member.size

    for relative_path, row in existing.items():
        if relative_path not in current_paths:
            session.delete(row)
