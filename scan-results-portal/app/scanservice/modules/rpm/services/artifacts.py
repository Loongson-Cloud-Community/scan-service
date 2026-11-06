from __future__ import annotations

from fastapi import HTTPException
from fastapi.responses import Response

from ....artifact_stream import artifact_stream_response
from ....config import get_settings
from ....jenkins import JenkinsClient
from ..models import RpmScanArtifact, RpmScanTask


def get_artifact(task: RpmScanTask, artifact_id: int) -> RpmScanArtifact:
    artifact = next((row for row in task.artifacts if row.id == artifact_id), None)
    if artifact is None:
        raise HTTPException(status_code=404, detail="RPM scan artifact not found")
    return artifact


def artifact_response(
    task: RpmScanTask,
    artifact: RpmScanArtifact,
    *,
    download: bool,
) -> Response:
    settings = get_settings()
    max_bytes = settings.artifact_limits.max_download_bytes
    if artifact.size_bytes is not None and artifact.size_bytes > max_bytes:
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
        artifact.relative_path,
        max_bytes=max_bytes,
    )
    return artifact_stream_response(
        client,
        chunks,
        artifact_type=artifact.artifact_type,
        filename=artifact.name,
        download=download,
    )
