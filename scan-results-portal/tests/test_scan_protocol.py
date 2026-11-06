import asyncio
from copy import deepcopy
import json

from fastapi import FastAPI
import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from conftest import (
    RPM_SCAN_KEY, FakeJenkinsClient,
    rpm_manifest, rpm_scan_artifacts, srpm_scan_artifacts,
)
from scanservice.db import Base, get_db
from scanservice import completion_sync
from scanservice.modules.rpm.api import routes as rpm_routes
from scanservice.modules.rpm.models import RpmScanTask, RpmScanVulnerability
from scanservice.modules.rpm.parsers.cve_bin_tool import parse_manifest
from scanservice.modules.rpm.schemas.events import RpmEventRequest
from scanservice.modules.rpm.services.synchronization import sync_task
from scanservice.modules.rpm.services import events as rpm_events
from scanservice.modules.srpm.api import routes as srpm_routes
from scanservice.modules.srpm.models import SrpmScanTask
from scanservice.modules.srpm.schemas.events import SrpmEventRequest
from scanservice.modules.srpm.services.sync_results import set_manifest
from scanservice.modules.srpm.services import events as srpm_events
from scanservice.modules.srpm.services.synchronization import sync_build
from scanservice.security import require_ingest_token


def event_values(kind, **overrides):
    values = {
        "event": "started", "jenkins_job_full_name": "packages/curl",
        "jenkins_build_number": 7,
    }
    if kind == "rpm":
        values.update(scan_key=RPM_SCAN_KEY, rpm_sha256=RPM_SCAN_KEY,
                      rpm_name="docker-24.0.9-8.lns23.loongarch64.rpm")
    else:
        values["srpm_name"] = "curl-8.4.0-9.ocs23.src.rpm"
    return {**values, **overrides}


@pytest.fixture
def http_session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        yield db
    engine.dispose()


@pytest.fixture
def event_app(http_session, settings, monkeypatch):
    monkeypatch.setattr(completion_sync, "SessionLocal", sessionmaker(bind=http_session.get_bind()))
    app = FastAPI()
    for routes in (rpm_routes, srpm_routes):
        monkeypatch.setattr(routes, "get_settings", lambda: settings)
        app.include_router(routes.router)
    app.dependency_overrides[get_db] = lambda: http_session
    app.dependency_overrides[require_ingest_token] = lambda: None
    return app


@pytest.mark.parametrize("model,kind", [(RpmEventRequest, "rpm"), (SrpmEventRequest, "srpm")])
@pytest.mark.parametrize("changes", [
    {"jenkins_job_full_name": ""}, {"jenkins_job_full_name": "   "},
    {"jenkins_job_full_name": "packages/../curl"}, {"jenkins_job_full_name": "x//curl"},
    {"jenkins_job_full_name": "x\ncurl"}, {"jenkins_job_full_name": "x" * 501},
    {"jenkins_job_full_name": 123}, {"jenkins_build_number": True},
    {"jenkins_build_number": 1.5}, {"jenkins_build_number": "7"},
    {"jenkins_build_number": 2**31},
    {"created_at": "2026-10-01T10:00:00"},
    {"created_at": True}, {"finished_at": 123},
])
def test_event_rejects_invalid_common_fields(model, kind, changes):
    with pytest.raises(ValidationError):
        model(**event_values(kind, **changes))


@pytest.mark.parametrize("changes", [
    {"rpm_sha256": "z" * 64}, {"scan_key": "../scan"},
    {"rpm_sha256": RPM_SCAN_KEY + "\n"},
    {"scan_key": "b" * 64}, {"rpm_name": "../package.rpm"},
    {"rpm_name": "package\n.rpm"}, {"rpm_name": 123},
    {"rpm_name": "package.rpm\n"},
    {"cbt_exit_code": True}, {"cbt_exit_code": "0"},
    {"cbt_exit_code": 2**31},
])
def test_rpm_event_rejects_invalid_identity_and_exit_code(changes):
    with pytest.raises(ValidationError):
        RpmEventRequest(**event_values("rpm", **changes))


@pytest.mark.parametrize("changes", [
    {"srpm_name": "../curl.src.rpm"}, {"srpm_name": "curl\n.src.rpm"},
    {"srpm_name": "curl.rpm"}, {"srpm_name": 123},
    {"srpm_name": "curl.src.rpm\n"},
    {"csmock_exit_code": True}, {"csmock_exit_code": "0"},
])
def test_srpm_event_rejects_invalid_identity_and_exit_code(changes):
    with pytest.raises(ValidationError):
        SrpmEventRequest(**event_values("srpm", **changes))


@pytest.mark.parametrize("path,value", [
    (("schema_version",), None), (("schema_version",), 2),
    (("schema_version",), True), (("schema_version",), "1"),
    (("rpm", "filename"), ["package.rpm"]), (("rpm", "sha256"), "z" * 64),
    (("rpm", "size_bytes"), "100"), (("rpm", "size_bytes"), -1),
    (("rpm", "name"), {}), (("rpm", "version"), "x" * 201),
    (("scanner", "exit_code"), None), (("scanner", "exit_code"), True),
    (("scanner", "exit_code"), "0"), (("scanner", "args"), "--update never"),
    (("scanner", "args"), [123]),
])
def test_rpm_manifest_rejects_invalid_versions_and_types(path, value):
    manifest = rpm_manifest()
    parent = manifest
    for part in path[:-1]:
        parent = parent[part]
    parent[path[-1]] = value
    with pytest.raises(ValueError):
        parse_manifest(json.dumps(manifest).encode())


def test_rpm_manifest_requires_schema_version():
    manifest = rpm_manifest()
    del manifest["schema_version"]
    with pytest.raises(ValueError):
        parse_manifest(json.dumps(manifest).encode())


@pytest.mark.parametrize("kind", ["rpm", "srpm"])
@pytest.mark.parametrize("event", ["started", "completed", "failed"])
def test_http_rejects_conflicting_package_without_mutation(http_session, event_app, kind, event):
    session = http_session
    model = RpmScanTask if kind == "rpm" else SrpmScanTask
    field = "rpm_name" if kind == "rpm" else "srpm_name"
    values = event_values(kind)

    async def exchange():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=event_app), base_url="http://test") as client:
            started = await client.post(f"/api/v1/{kind}/events", json=values)
            assert started.status_code == 200
            conflict = await client.post(f"/api/v1/{kind}/events", json={
                **values, "event": event, field: "other.src.rpm" if kind == "srpm" else "other.rpm",
            })
            assert conflict.status_code == 409

    asyncio.run(exchange())
    session.expire_all()
    task = session.scalars(select(model)).one()
    assert getattr(task, field) == values[field]
    assert getattr(task, "state" if kind == "rpm" else "scan_result") == "RUNNING"
    assert task.finished_at is None


@pytest.mark.parametrize("kind", ["rpm", "srpm"])
def test_http_invalid_event_is_422_without_creating_task(http_session, event_app, kind):
    async def exchange():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=event_app), base_url="http://test") as client:
            response = await client.post(f"/api/v1/{kind}/events", json=event_values(
                kind, jenkins_build_number=True,
            ))
            assert response.status_code == 422

    asyncio.run(exchange())
    assert http_session.scalars(select(RpmScanTask)).all() == []
    assert http_session.scalars(select(SrpmScanTask)).all() == []


@pytest.mark.parametrize("kind", ["rpm", "srpm"])
def test_http_current_agent_event_sequence_still_finishes(http_session, event_app, monkeypatch, kind):
    if kind == "rpm":
        artifacts, contents = rpm_scan_artifacts()
        module, exit_field = rpm_events, "cbt_exit_code"
    else:
        artifacts, contents = srpm_scan_artifacts(build_number=7)
        module, exit_field = srpm_events, "csmock_exit_code"
    fake = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    monkeypatch.setattr(module, "JenkinsClient", lambda *args, **kwargs: fake)
    values = event_values(kind, created_at="2026-10-01T10:00:00+08:00")

    async def exchange():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=event_app), base_url="http://test") as client:
            started = await client.post(f"/api/v1/{kind}/events", json=values)
            assert started.status_code == 200
            completed = await client.post(f"/api/v1/{kind}/events", json={
                **values, "event": "completed", "finished_at": "2026-10-01T10:05:00+08:00",
                exit_field: 0,
            })
            assert completed.status_code == 200
            assert completed.json()["sync_status"] == "PENDING"
            session = http_session
            session.expire_all()
            model = RpmScanTask if kind == "rpm" else SrpmScanTask
            task = session.scalars(select(model)).one()
            assert getattr(task, "state" if kind == "rpm" else "scan_result") == "FINISHED"
            retried = await client.post(f"/api/v1/{kind}/events", json={
                **values, "event": "completed", exit_field: 0,
            })
            assert retried.status_code == 200
            assert len(fake.requested_builds) == 1
            assert fake.closed

    asyncio.run(exchange())


def test_manifest_package_mismatch_does_not_replace_rpm_results(session):
    artifacts, contents = rpm_scan_artifacts()
    path = next(path for path in contents if path.endswith("scan-manifest.json"))
    manifest = json.loads(contents[path])
    manifest["rpm"]["filename"] = "other.rpm"
    contents[path] = json.dumps(manifest).encode()
    task = RpmScanTask(
        scan_key=RPM_SCAN_KEY, rpm_sha256=RPM_SCAN_KEY,
        jenkins_job_full_name="packages/curl", jenkins_build_number=7,
        rpm_name="docker-24.0.9-8.lns23.loongarch64.rpm", state="RUNNING",
    )
    session.add(task)
    session.flush()
    with pytest.raises(ValueError, match="filename"):
        sync_task(session, FakeJenkinsClient(artifacts=artifacts, contents=contents), task)
    assert task.rpm_name == "docker-24.0.9-8.lns23.loongarch64.rpm"
    assert session.scalars(select(RpmScanVulnerability)).all() == []


@pytest.mark.parametrize("manifest", [
    {"schema_version": 2}, {"srpm_name": ["curl.src.rpm"]},
    {"scanner": {"name": "other"}}, {"csmock_exit_code": True},
    {"srpm_name": "other.src.rpm"}, {"jenkins_build_number": 9},
])
def test_optional_srpm_manifest_is_validated_before_any_assignment(manifest):
    task = SrpmScanTask(
        jenkins_job_full_name="packages/curl", jenkins_build_number=7,
        srpm_name="curl-8.4.0-9.ocs23.src.rpm", scanner_version="original",
    )
    with pytest.raises(ValueError):
        set_manifest(task, {"scanner_version": "changed", **deepcopy(manifest)})
    assert task.scanner_version == "original"
    assert task.srpm_name == "curl-8.4.0-9.ocs23.src.rpm"


@pytest.mark.parametrize("identity,value", [
    ("jenkins_job_full_name", "other/job"), ("jenkins_build_number", 99),
    ("scan_key", "b" * 64),
])
def test_rpm_manifest_location_must_match_registered_scan(session, identity, value):
    artifacts, contents = rpm_scan_artifacts()
    path = next(path for path in contents if path.endswith("scan-manifest.json"))
    manifest = json.loads(contents[path])
    manifest[identity] = value
    contents[path] = json.dumps(manifest).encode()
    task = RpmScanTask(
        scan_key=RPM_SCAN_KEY, rpm_sha256=RPM_SCAN_KEY,
        jenkins_job_full_name="packages/curl", jenkins_build_number=7,
        rpm_name=manifest["rpm"]["filename"], state="RUNNING",
    )
    session.add(task)
    session.flush()
    with pytest.raises(ValueError, match=identity):
        sync_task(session, FakeJenkinsClient(artifacts=artifacts, contents=contents), task)
    assert task.scanner is None


def test_srpm_archive_project_must_match_registered_package(session, settings):
    artifacts, contents = srpm_scan_artifacts(build_number=7, nvr="other-1-1")
    task = SrpmScanTask(
        jenkins_job_full_name="packages/other", jenkins_build_number=7,
        srpm_name="other-1-1.src.rpm", scan_result="RUNNING",
    )
    session.add(task)
    session.flush()
    # The archive filename matches, but scan.ini still belongs to curl.
    sync_build(session, FakeJenkinsClient(artifacts=artifacts, contents=contents),
               settings, 7, job_full_name="packages/other")
    assert task.scan_result == "NOT_AVAILABLE"
    assert task.total_findings is None
    assert "project-name" in task.sync_error


def test_manifest_cannot_turn_reported_rpm_failure_into_success(session):
    artifacts, contents = rpm_scan_artifacts()
    task = RpmScanTask(
        scan_key=RPM_SCAN_KEY, rpm_sha256=RPM_SCAN_KEY,
        jenkins_job_full_name="packages/curl", jenkins_build_number=7,
        rpm_name="docker-24.0.9-8.lns23.loongarch64.rpm", state="RUNNING",
        cbt_exit_code=2,
    )
    session.add(task)
    session.flush()
    sync_task(session, FakeJenkinsClient(artifacts=artifacts, contents=contents), task)
    assert task.state == "FAILED"
    assert task.cbt_exit_code == 2
