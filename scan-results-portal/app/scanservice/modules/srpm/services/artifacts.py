from __future__ import annotations

import tarfile

from fastapi import HTTPException
from fastapi.responses import HTMLResponse, Response

from ....artifact_stream import artifact_stream_response
from ..csmock.archive import ArchiveLimitError, list_visible_members, read_visible_member
from ....config import get_settings
from ....jenkins import JenkinsArtifactTooLarge, JenkinsClient
from ....artifact_policy import artifact_response_options
from ..models import SrpmScanArtifact, SrpmScanTask


def get_artifact_row(task: SrpmScanTask, artifact_id: int) -> SrpmScanArtifact:
    row = next((item for item in task.artifacts if item.id == artifact_id), None)
    if row is None:
        raise HTTPException(status_code=404, detail="artifact not found")
    return row


def read_artifact_content(task: SrpmScanTask, row: SrpmScanArtifact) -> bytes:
    source_path = row.relative_path
    member_path = None
    if "::" in source_path:
        source_path, _, member_path = source_path.partition("::")
        archive_row = next(
            (
                item
                for item in task.artifacts
                if item.relative_path == source_path and "::" not in item.relative_path
            ),
            None,
        )
        if archive_row is None:
            raise HTTPException(status_code=404, detail="source archive not found")

    if not task.jenkins_job_full_name or task.jenkins_build_number is None:
        raise HTTPException(status_code=404, detail="artifact source not found")

    settings = get_settings()
    limits = settings.artifact_limits
    if member_path and archive_row.size_bytes is not None:
        if archive_row.size_bytes > limits.max_archive_bytes:
            raise HTTPException(status_code=413, detail="archive is too large to inspect")
    client = JenkinsClient(
        settings.jenkins_base_url,
        settings.jenkins_user,
        settings.jenkins_token,
        settings.request_timeout_seconds,
    )
    try:
        content = client.get_artifact(
            task.jenkins_job_full_name,
            task.jenkins_build_number,
            source_path,
            max_bytes=limits.max_archive_bytes if member_path else limits.max_download_bytes,
        )
    except (ArchiveLimitError, JenkinsArtifactTooLarge) as exc:
        raise HTTPException(status_code=413, detail="artifact exceeds resource limits") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="unable to read artifact") from exc
    finally:
        client.close()

    if member_path is None:
        return content
    try:
        visible = {item.path for item in list_visible_members(content, limits)}
        if member_path not in visible:
            raise KeyError(member_path)
        return read_visible_member(content, member_path, limits)
    except ArchiveLimitError as exc:
        raise HTTPException(status_code=413, detail="archive exceeds resource limits") from exc
    except (KeyError, OSError, ValueError, tarfile.TarError) as exc:
        raise HTTPException(status_code=404, detail="archive member not found") from exc


def artifact_response(task: SrpmScanTask, row: SrpmScanArtifact, *, download: bool) -> Response:
    filename = (row.name or "artifact").replace('"', "'")
    if not download and row.artifact_type == "ARCHIVE":
        return HTMLResponse(
            "<p>This artifact cannot be viewed online. "
            "Use the <b>[download]</b> link to download it.</p>"
        )
    if "::" in row.relative_path:
        content = read_artifact_content(task, row)
        options = artifact_response_options(
            artifact_type=row.artifact_type,
            filename=filename,
            download=download,
        )
        return Response(content=content, **options)

    if not task.jenkins_job_full_name or task.jenkins_build_number is None:
        raise HTTPException(status_code=404, detail="artifact source not found")
    settings = get_settings()
    max_bytes = settings.artifact_limits.max_download_bytes
    if row.size_bytes is not None and row.size_bytes > max_bytes:
        raise HTTPException(status_code=413, detail="artifact is too large to serve")
    client = JenkinsClient(
        settings.jenkins_base_url,
        settings.jenkins_user,
        settings.jenkins_token,
        settings.request_timeout_seconds,
    )
    chunks = client.iter_artifact(
        task.jenkins_job_full_name,
        task.jenkins_build_number,
        row.relative_path,
        max_bytes=max_bytes,
    )
    return artifact_stream_response(
        client,
        chunks,
        artifact_type=row.artifact_type,
        filename=filename,
        download=download,
    )


def archive_member_response(task: SrpmScanTask, archive_ref: str) -> Response:
    archive_path, separator, member_path = archive_ref.partition("::")
    if not separator or not archive_path or not member_path:
        raise HTTPException(status_code=404, detail="invalid archive member")

    archive_row = next(
        (
            row
            for row in task.artifacts
            if row.relative_path == archive_path and "::" not in row.relative_path
        ),
        None,
    )
    if archive_row is None or not task.jenkins_job_full_name or task.jenkins_build_number is None:
        raise HTTPException(status_code=404, detail="archive not found")

    settings = get_settings()
    limits = settings.artifact_limits
    if archive_row.size_bytes is not None and archive_row.size_bytes > limits.max_archive_bytes:
        raise HTTPException(status_code=413, detail="archive is too large to inspect")
    client = JenkinsClient(
        settings.jenkins_base_url,
        settings.jenkins_user,
        settings.jenkins_token,
        settings.request_timeout_seconds,
    )
    try:
        content = client.get_artifact(
            task.jenkins_job_full_name,
            task.jenkins_build_number,
            archive_path,
            max_bytes=limits.max_archive_bytes,
        )
    except JenkinsArtifactTooLarge as exc:
        raise HTTPException(status_code=413, detail="archive exceeds resource limits") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail="unable to read archive") from exc
    finally:
        client.close()

    try:
        visible = {item.path for item in list_visible_members(content, limits)}
        if member_path not in visible:
            raise KeyError(member_path)
        member_content = read_visible_member(content, member_path, limits)
    except ArchiveLimitError as exc:
        raise HTTPException(status_code=413, detail="archive exceeds resource limits") from exc
    except (KeyError, OSError, ValueError, tarfile.TarError) as exc:
        raise HTTPException(status_code=404, detail="archive member not found") from exc

    filename = member_path.rsplit("/", 1)[-1]
    return Response(
        content=member_content,
        **artifact_response_options(
            artifact_type="OTHER", filename=filename, download=True
        ),
    )
