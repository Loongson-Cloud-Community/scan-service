from __future__ import annotations

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from conftest import FakeJenkinsClient, srpm_archive_bytes

from scanservice.db import Base, get_db
from scanservice.modules.rpm.api.routes import router as rpm_router
from scanservice.modules.rpm.models import (
    RpmScanArtifact, RpmScanComponent, RpmScanTask, RpmScanVulnerability,
)
from scanservice.modules.rpm.services import artifacts as rpm_artifacts
from scanservice.modules.srpm.api.routes import router as srpm_router
from scanservice.modules.srpm.models import (
    SrpmScanArtifact, SrpmScanFinding, SrpmScanSummary, SrpmScanTask,
)
from scanservice.modules.srpm.services import artifacts as srpm_artifacts


@pytest.fixture(params=["rpm", "srpm"])
def portal(request, settings, monkeypatch):
    kind = request.param
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    content = b"scan content\n"
    with Session(engine) as db:
        if kind == "rpm":
            task = RpmScanTask(
                scan_key="a" * 64, jenkins_job_full_name="demo", jenkins_build_number=1,
                rpm_name="demo.rpm", rpm_sha256="a" * 64, state="FINISHED",
                scan_metadata={"irrelevant": "x" * 10000},
            )
            other = RpmScanTask(
                scan_key="b" * 64, jenkins_job_full_name="other", jenkins_build_number=1,
                rpm_name="other.rpm", rpm_sha256="b" * 64, state="FINISHED",
            )
            artifact_model = RpmScanArtifact
            db.add_all([task, other])
            db.flush()
            db.add(RpmScanComponent(
                task_id=task.id, vendor="v", product="p", version="1",
                vulnerability_count=1,
            ))
            db.add(RpmScanVulnerability(
                task_id=task.id, fingerprint="c" * 64, vendor="v", product="p",
                version="1", cve_number="CVE-2026-0001", severity="HIGH",
                raw={"irrelevant": "x" * 10000},
            ))
        else:
            task = SrpmScanTask(
                jenkins_job_full_name="demo", jenkins_build_number=1,
                srpm_name="demo.src.rpm", scan_result="FINISHED",
                scan_metadata={"irrelevant": "x" * 10000},
            )
            other = SrpmScanTask(
                jenkins_job_full_name="other", jenkins_build_number=1,
                srpm_name="other.src.rpm", scan_result="FINISHED",
            )
            artifact_model = SrpmScanArtifact
            db.add_all([task, other])
            db.flush()
            db.add(SrpmScanSummary(task_id=task.id, checker="c", issue_type="i", count=1))
            db.add(SrpmScanFinding(
                task_id=task.id, fingerprint="c" * 64,
                raw={"irrelevant": "x" * 10000},
            ))
        artifact = artifact_model(
            task_id=task.id, name="scan.log", artifact_type="LOG", relative_path="scan.log",
        )
        foreign = artifact_model(
            task_id=other.id, name="foreign.log", artifact_type="LOG", relative_path="foreign.log",
        )
        db.add_all([artifact, foreign])
        if kind == "srpm":
            archive = SrpmScanArtifact(
                task_id=task.id, name="demo.tar.xz", artifact_type="ARCHIVE",
                relative_path="demo.tar.xz",
            )
            member = SrpmScanArtifact(
                task_id=task.id, name="scan.log", artifact_type="LOG",
                relative_path="demo.tar.xz::scan.log",
            )
            db.add_all([archive, member])
        db.commit()
        task_id, artifact_id, foreign_id = task.id, artifact.id, foreign.id
        member_id = member.id if kind == "srpm" else None

    client = FakeJenkinsClient(contents={
        "scan.log": content,
        "demo.tar.xz": srpm_archive_bytes({"scan.log": content.decode()}),
    })
    module = rpm_artifacts if kind == "rpm" else srpm_artifacts
    monkeypatch.setattr(module, "JenkinsClient", lambda *args, **kwargs: client)
    monkeypatch.setattr(module, "get_settings", lambda: settings)

    def sessions():
        with Session(engine) as db:
            yield db

    app = FastAPI()
    app.include_router(rpm_router if kind == "rpm" else srpm_router)
    app.dependency_overrides[get_db] = sessions
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    event.listen(engine, "before_cursor_execute", capture)
    yield SimpleNamespace(
        app=app, kind=kind, task_id=task_id, artifact_id=artifact_id,
        foreign_id=foreign_id, member_id=member_id, statements=statements,
        jenkins=client, content=content,
    )
    event.remove(engine, "before_cursor_execute", capture)
    engine.dispose()


async def get(portal, path):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=portal.app), base_url="http://portal"
    ) as client:
        return await client.get(path)


def assert_only_artifact_data_read(portal):
    assert not any(
        name in statement
        for statement in portal.statements
        for name in (
            "rpm_scan_component", "rpm_scan_vulnerability",
            "srpm_scan_summary", "srpm_scan_finding", "scan_metadata",
        )
    ), portal.statements
    assert 0 < len(portal.statements) <= 2


@pytest.mark.parametrize("action", ["view", "download"])
def test_direct_artifact_reads_only_delivery_data(portal, action):
    response = asyncio.run(get(
        portal,
        f"/api/v1/{portal.kind}/tasks/{portal.task_id}/artifacts/{portal.artifact_id}/{action}",
    ))

    assert response.status_code == 200
    assert response.content == portal.content
    assert_only_artifact_data_read(portal)


@pytest.mark.parametrize("target", ["member-view", "member-download", "archive"])
@pytest.mark.parametrize("portal", ["srpm"], indirect=True)
def test_archive_artifact_reads_only_delivery_data(portal, target):
    base = f"/api/v1/srpm/tasks/{portal.task_id}"
    if target == "archive":
        path = f"{base}/archive/demo.tar.xz::scan.log"
    else:
        action = "view" if target == "member-view" else "download"
        path = f"{base}/artifacts/{portal.member_id}/{action}"

    response = asyncio.run(get(portal, path))

    assert response.status_code == 200
    assert response.content == portal.content
    assert_only_artifact_data_read(portal)


@pytest.mark.parametrize("portal", ["srpm"], indirect=True)
def test_artifact_list_does_not_load_scan_results(portal):
    response = asyncio.run(get(
        portal, f"/api/v1/srpm/tasks/{portal.task_id}/artifacts"
    ))

    assert response.status_code == 200
    assert {row["id"] for row in response.json()} >= {portal.artifact_id, portal.member_id}
    assert portal.foreign_id not in {row["id"] for row in response.json()}
    assert portal.jenkins.requested_artifacts == []
    assert_only_artifact_data_read(portal)


def test_artifact_from_another_task_is_not_accessible(portal):
    response = asyncio.run(get(
        portal,
        f"/api/v1/{portal.kind}/tasks/{portal.task_id}/artifacts/{portal.foreign_id}/download",
    ))

    assert response.status_code == 404
    assert portal.jenkins.requested_artifacts == []
    assert_only_artifact_data_read(portal)


def test_missing_task_does_not_fetch_artifacts(portal):
    response = asyncio.run(get(
        portal,
        f"/api/v1/{portal.kind}/tasks/99999/artifacts/{portal.artifact_id}/download",
    ))

    assert response.status_code == 404
    assert portal.jenkins.requested_artifacts == []
    assert len(portal.statements) == 1
