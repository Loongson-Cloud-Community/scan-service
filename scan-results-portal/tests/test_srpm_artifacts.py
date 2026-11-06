import asyncio

import pytest

from conftest import FakeJenkinsClient, response_body, srpm_archive_bytes

from scanservice.modules.srpm.models import SrpmScanArtifact, SrpmScanTask
from scanservice.modules.srpm.services import artifacts as artifacts_module
from scanservice.modules.srpm.services.artifacts import (
    archive_member_response,
    artifact_response,
)


def _task_with_artifact(session, monkeypatch, name, artifact_type, content):
    task = SrpmScanTask(
        jenkins_job_full_name="csmock-curl-test",
        jenkins_build_number=6,
        srpm_name="curl-8.4.0-9.ocs23.src.rpm",
        scan_result="FINISHED",
        sync_status="SYNCED",
    )
    session.add(task)
    session.flush()
    row = SrpmScanArtifact(
        task=task,
        name=name,
        artifact_type=artifact_type,
        relative_path=name,
    )
    session.add(row)
    session.commit()

    client = FakeJenkinsClient(contents={name: content})
    monkeypatch.setattr(artifacts_module, "JenkinsClient", lambda *args, **kwargs: client)
    return task, row


@pytest.mark.parametrize(
    ("name", "artifact_type"),
    [
        ("scan.ini", "METADATA"),
        ("scan-results-summary.txt", "SUMMARY"),
        ("scan-results.js", "REPORT_JSON"),
        ("scan.log", "LOG"),
    ],
)
def test_view_serves_text_artifacts_inline(session, monkeypatch, name, artifact_type):
    task, row = _task_with_artifact(
        session, monkeypatch, name, artifact_type, b"content\n"
    )

    response = artifact_response(task, row, download=False)

    assert response.headers["content-type"] == "text/plain; charset=utf-8"
    assert response.headers["content-disposition"] == f'inline; filename="{name}"'
    assert asyncio.run(response_body(response)) == b"content\n"


def test_view_of_an_archive_points_to_the_download_link(session, monkeypatch):
    task, row = _task_with_artifact(
        session, monkeypatch, "curl-8.4.0-9.ocs23.tar.xz", "ARCHIVE", b""
    )

    response = artifact_response(task, row, download=False)

    assert b"cannot be viewed online" in response.body


def test_download_of_an_archive_is_an_attachment(session, monkeypatch):
    content = srpm_archive_bytes()
    task, row = _task_with_artifact(
        session, monkeypatch, "curl-8.4.0-9.ocs23.tar.xz", "ARCHIVE", content
    )

    response = artifact_response(task, row, download=True)

    assert (
        response.headers["content-disposition"]
        == 'attachment; filename="curl-8.4.0-9.ocs23.tar.xz"'
    )
    assert asyncio.run(response_body(response)) == content


def test_archive_member_download_is_an_attachment(session, monkeypatch):
    task, row = _task_with_artifact(
        session, monkeypatch, "curl-8.4.0-9.ocs23.tar.xz", "ARCHIVE", srpm_archive_bytes()
    )

    response = archive_member_response(task, f"{row.relative_path}::scan.log")

    assert response.headers["content-disposition"] == 'attachment; filename="scan.log"'
    assert response.body == b"log\n"


@pytest.mark.parametrize(
    ("name", "artifact_type", "media_type"),
    [
        ("scan-results.html", "REPORT_HTML", "text/html; charset=utf-8"),
        ("preview.svg", "OTHER", "image/svg+xml"),
        ("preview.xhtml", "OTHER", "application/xhtml+xml"),
    ],
)
@pytest.mark.parametrize("in_archive", [False, True])
def test_active_reports_are_sandboxed(
    session, monkeypatch, name, artifact_type, media_type, in_archive
):
    content = b"<html>report</html>"
    if in_archive:
        archive_content = srpm_archive_bytes({f"curl/{name}": content.decode()})
        task, archive = _task_with_artifact(
            session, monkeypatch, "curl.tar.xz", "ARCHIVE", archive_content
        )
        row = SrpmScanArtifact(
            task=task,
            name=name,
            artifact_type=artifact_type,
            relative_path=f"{archive.relative_path}::curl/{name}",
        )
        session.add(row)
        session.flush()
    else:
        task, row = _task_with_artifact(
            session, monkeypatch, name, artifact_type, content
        )

    response = artifact_response(task, row, download=False)

    assert response.headers["content-type"] == media_type
    assert response.headers["content-disposition"] == f'inline; filename="{name}"'
    assert response.headers["x-content-type-options"] == "nosniff"
    policy = response.headers["content-security-policy"]
    assert policy.startswith("sandbox allow-scripts;")
    assert "allow-same-origin" not in policy
    assert "script-src 'unsafe-inline'" in policy
    assert "connect-src 'none'" in policy
    assert asyncio.run(response_body(response)) == content


def test_unknown_format_is_downloaded_instead_of_rendered(session, monkeypatch):
    task, row = _task_with_artifact(
        session, monkeypatch, "unknown.bin", "OTHER", b"<html>unknown</html>"
    )

    response = artifact_response(task, row, download=False)

    assert response.headers["content-type"] == "application/octet-stream"
    assert response.headers["content-disposition"] == 'attachment; filename="unknown.bin"'
    assert response.headers["x-content-type-options"] == "nosniff"
    assert asyncio.run(response_body(response)) == b"<html>unknown</html>"


def test_archive_html_download_stays_an_attachment(session, monkeypatch):
    content = srpm_archive_bytes({"curl/scan-results.html": "<html>report</html>"})
    task, archive = _task_with_artifact(
        session, monkeypatch, "curl.tar.xz", "ARCHIVE", content
    )

    response = archive_member_response(
        task, f"{archive.relative_path}::curl/scan-results.html"
    )

    assert response.headers["content-type"] == "text/html; charset=utf-8"
    assert response.headers["content-disposition"] == 'attachment; filename="scan-results.html"'
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.body == b"<html>report</html>"
