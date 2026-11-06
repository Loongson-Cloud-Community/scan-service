import asyncio

import pytest
from fastapi import HTTPException

from conftest import RPM_BUILD_NUMBER, RPM_SCAN_KEY, FakeJenkinsClient, response_body

from scanservice.modules.rpm.models import RpmScanArtifact, RpmScanTask
from scanservice.modules.rpm.services import artifacts as artifacts_module
from scanservice.modules.rpm.services.artifacts import artifact_response


def _task_with_artifact(session, monkeypatch, name, artifact_type, content):
    task = RpmScanTask(
        scan_key=RPM_SCAN_KEY,
        jenkins_job_full_name="rpm-docker-test",
        jenkins_build_number=7,
        rpm_name="docker-24.0.9-8.lns23.loongarch64.rpm",
        rpm_sha256=RPM_SCAN_KEY,
        state="FINISHED",
        sync_status="SYNCED",
    )
    session.add(task)
    session.flush()
    relative_path = f"rpm-scan-artifacts/{RPM_BUILD_NUMBER}/{RPM_SCAN_KEY}/{name}"
    row = RpmScanArtifact(
        task=task,
        name=name,
        artifact_type=artifact_type,
        relative_path=relative_path,
    )
    session.add(row)
    session.commit()

    client = FakeJenkinsClient(contents={relative_path: content})
    monkeypatch.setattr(artifacts_module, "JenkinsClient", lambda *args, **kwargs: client)
    return task, row


@pytest.mark.parametrize(
    ("name", "artifact_type"),
    [
        ("scan-manifest.json", "METADATA"),
        ("scan-results.json", "REPORT_JSON"),
        ("scan-results.csv", "REPORT_CSV"),
        ("scan.log", "LOG"),
    ],
)
def test_view_serves_text_artifacts_inline(session, monkeypatch, name, artifact_type):
    # Browsers download text/csv, application/json and octet-stream payloads,
    # so the view link has to serve them as text/plain.
    task, row = _task_with_artifact(
        session, monkeypatch, name, artifact_type, b"content\n"
    )

    response = artifact_response(task, row, download=False)

    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.headers["content-disposition"] == f'inline; filename="{name}"'
    assert asyncio.run(response_body(response)) == b"content\n"


def test_view_serves_html_with_its_own_type_and_sandbox(session, monkeypatch):
    task, row = _task_with_artifact(
        session, monkeypatch, "scan-results.html", "REPORT_HTML", b"<html></html>"
    )

    response = artifact_response(task, row, download=False)

    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert (
        response.headers["content-disposition"]
        == 'inline; filename="scan-results.html"'
    )
    policy = response.headers["content-security-policy"]
    assert policy.startswith("sandbox allow-scripts;")
    assert "script-src 'unsafe-inline'" in policy
    assert "connect-src 'none'" in policy
    assert "allow-same-origin" not in policy
    assert response.headers["x-content-type-options"] == "nosniff"
    assert asyncio.run(response_body(response)) == b"<html></html>"


def test_download_keeps_original_media_type_and_attachment(session, monkeypatch):
    task, row = _task_with_artifact(
        session, monkeypatch, "scan-results.csv", "REPORT_CSV", b"vendor,product\n"
    )

    response = artifact_response(task, row, download=True)

    assert response.headers["content-type"] == "text/csv; charset=utf-8"
    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="scan-results.csv"'
    )
    assert asyncio.run(response_body(response)) == b"vendor,product\n"


def test_known_oversized_artifact_is_rejected(session, monkeypatch, settings):
    task, row = _task_with_artifact(
        session, monkeypatch, "scan.log", "LOG", b"content"
    )
    row.size_bytes = settings.artifact_limits.max_download_bytes + 1
    monkeypatch.setattr(artifacts_module, "get_settings", lambda: settings)

    with pytest.raises(HTTPException) as exc_info:
        artifact_response(task, row, download=True)

    assert exc_info.value.status_code == 413


def test_unknown_format_is_downloaded_instead_of_rendered(session, monkeypatch):
    task, row = _task_with_artifact(
        session, monkeypatch, "unknown.bin", "OTHER", b"<html>unknown</html>"
    )

    response = artifact_response(task, row, download=False)

    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"] == 'attachment; filename="unknown.bin"'
    assert response.headers["x-content-type-options"] == "nosniff"
    assert asyncio.run(response_body(response)) == b"<html>unknown</html>"
