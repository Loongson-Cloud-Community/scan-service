"""Public reads must load only the data their response actually uses."""

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

from fastapi import FastAPI
from fastapi.encoders import jsonable_encoder
import httpx
import pytest
from sqlalchemy import event
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import Session

from scanservice.db import get_db
from scanservice.modules.rpm.api import routes as rpm_api
from scanservice.modules.rpm.models import (
    RpmScanArtifact, RpmScanComponent, RpmScanTask, RpmScanVulnerability,
)
from scanservice.modules.rpm.services.task_service import task_payload as rpm_payload
from scanservice.modules.rpm.services import task_queries as rpm_queries
from scanservice.modules.rpm.web import routes as rpm_web
from scanservice.modules.srpm.api import routes as srpm_api
from scanservice.modules.srpm.models import (
    SrpmScanArtifact, SrpmScanFinding, SrpmScanSummary, SrpmScanTask,
)
from scanservice.modules.srpm.services.task_service import task_payload as srpm_payload
from scanservice.modules.srpm.services import task_queries as srpm_queries
from scanservice.modules.srpm.web import routes as srpm_web


EXPECTED_FIELDS = {
    "rpm": {
        "id",
        "scan_key",
        "jenkins_job_full_name",
        "jenkins_build_number",
        "rpm_name",
        "rpm_sha256",
        "state",
        "scanner",
        "scanner_version",
        "total_vulnerabilities",
        "component_count",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "unknown_count",
        "created_at",
        "finished_at",
        "sync_status",
    },
    "srpm": {
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
    },
}

@pytest.fixture(params=["rpm", "srpm"])
def portal(request, query_engine, settings, monkeypatch):
    kind = request.param
    api, web = (rpm_api, rpm_web) if kind == "rpm" else (srpm_api, srpm_web)
    with Session(query_engine) as db:
        timestamp = datetime(2026, 11, 6, 10, tzinfo=timezone.utc)
        if kind == "rpm":
            task = RpmScanTask(
                scan_key="a" * 64, rpm_sha256="a" * 64, rpm_name="demo.rpm",
                jenkins_job_full_name="packages/demo", jenkins_build_number=7,
                state="FINISHED", scanner="cve-bin-tool", total_vulnerabilities=1,
                critical_count=0, high_count=1, medium_count=0, low_count=0,
                unknown_count=0, scanner_args=["--update", "never"],
                name="demo", epoch="1", version="2", release="3",
                architecture="loongarch64", source_rpm="demo.src.rpm",
                triggered_by="test-user", created_at=timestamp, finished_at=timestamp,
                scan_metadata={"large": "x" * 20000}, sync_error="unused error",
            )
            other = RpmScanTask(
                scan_key="b" * 64, rpm_sha256="b" * 64, rpm_name="other.rpm",
                jenkins_job_full_name="packages/other", jenkins_build_number=7,
                state="FAILED",
            )
            artifact_model = RpmScanArtifact
        else:
            task = SrpmScanTask(
                jenkins_job_full_name="packages/demo", jenkins_build_number=7,
                srpm_name="demo.src.rpm", scan_result="FINISHED", total_findings=1,
                scan_metadata={"manifest": {"method": "custom-csmock"},
                               "scan_ini": {"tool-args": "csmock --test"},
                               "large": "x" * 20000},
                enabled_plugins=["gcc"], mock_config="test-mock",
                triggered_by="test-user", created_at=timestamp, finished_at=timestamp,
                sync_error="unused error",
            )
            other = SrpmScanTask(
                jenkins_job_full_name="packages/other", jenkins_build_number=7,
                srpm_name="other.src.rpm", scan_result="FAILED",
            )
            artifact_model = SrpmScanArtifact
        db.add_all([task, other])
        db.flush()
        db.add(artifact_model(task_id=task.id, name="scan.log", relative_path="scan.log",
                              artifact_type="LOG", jenkins_url="http://private/artifact"))
        if kind == "rpm":
            db.add(RpmScanComponent(task_id=task.id, vendor="vendor", product="product",
                                    version="2", vulnerability_count=1))
            db.add(RpmScanVulnerability(
                task_id=task.id, fingerprint="c" * 64, vendor="vendor", product="product",
                version="2", cve_number="CVE-2026-0001", severity="HIGH", score=7.5,
                source="test-source", description="visible description",
                paths="/usr/bin/demo", cvss_vector="visible vector",
                comments="not displayed", raw={"large": "x" * 20000},
            ))
        else:
            for parent in (task, other):
                db.add(SrpmScanSummary(task_id=parent.id, checker="gcc",
                                       issue_type="warning", count=1))
                db.add(SrpmScanFinding(
                    task_id=parent.id, fingerprint="c" * 64, checker="gcc",
                    rule_id="test-rule", severity="warning", message="visible finding",
                    file_path="main.c", line=12, column=3, code_context="context",
                    raw={"large": "x" * 20000},
                ))
        db.commit()
        db.refresh(task)
        payload = rpm_payload if kind == "rpm" else srpm_payload
        expected = jsonable_encoder(payload(task))
        assert set(expected) == EXPECTED_FIELDS[kind]
        task_id = task.id

    def database():
        with Session(query_engine) as db:
            yield db

    monkeypatch.setattr(web, "get_settings", lambda: settings)
    app = FastAPI()
    app.include_router(api.router)
    app.include_router(web.router)
    app.dependency_overrides[get_db] = database
    statements = []

    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    event.listen(query_engine, "before_cursor_execute", capture)
    try:
        yield SimpleNamespace(kind=kind, app=app, id=task_id, expected=expected,
                              statements=statements, engine=query_engine)
    finally:
        event.remove(query_engine, "before_cursor_execute", capture)


def get(portal, path):
    async def exchange():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=portal.app),
                                     base_url="http://test") as client:
            return await client.get(path)
    return asyncio.run(exchange())


def assert_not_read(portal, *names):
    assert not any(name in sql for sql in portal.statements for name in names), portal.statements


def test_metadata_detail_preserves_payload_without_loading_results(portal):
    response = get(portal, f"/api/v1/{portal.kind}/tasks/{portal.id}")
    assert response.status_code == 200
    assert response.json() == portal.expected
    assert len(portal.statements) == 1
    assert_not_read(portal, "scan_artifact", "scan_component", "scan_vulnerability", "scan_summary",
                    "scan_finding", "scan_metadata", "sync_error", "scanner_args")


def test_metadata_reader_rejects_unrequested_lazy_loads(portal):
    queries = rpm_queries if portal.kind == "rpm" else srpm_queries
    with Session(portal.engine) as db:
        task = queries.get_task_metadata(db, portal.id)
        for name in ("scan_metadata", "artifacts", "vulnerabilities" if portal.kind == "rpm" else "findings"):
            with pytest.raises(InvalidRequestError):
                getattr(task, name)
    assert len(portal.statements) == 1


def test_api_task_list_reads_only_public_metadata(portal):
    response = get(portal, f"/api/v1/{portal.kind}/tasks?search=demo")
    assert response.status_code == 200
    assert response.json() == {"page": 1, "page_size": 50, "total": 1, "items": [portal.expected]}
    assert len(portal.statements) == 2
    assert_not_read(portal, "scan_artifact", "scan_component", "scan_vulnerability", "scan_summary",
                    "scan_finding", "scan_metadata", "sync_error", "scanner_args")


def test_web_list_preserves_visible_fields_without_reading_results(portal):
    response = get(portal, f"/{portal.kind}?search=demo")
    assert response.status_code == 200
    assert "demo." in response.text
    assert "FINISHED" in response.text
    assert ("custom-csmock" if portal.kind == "srpm" else "cve-bin-tool") in response.text
    assert len(portal.statements) == 2
    assert_not_read(portal, "scan_artifact", "scan_component", "scan_vulnerability", "scan_summary",
                    "scan_finding", "sync_error", "scanner_args")


def test_web_detail_loads_only_visible_result_data(portal):
    response = get(portal, f"/{portal.kind}/{portal.id}")
    assert response.status_code == 200
    for text in ("Details", "Results", "Logs", "demo.", "test-user", "scan.log", "[download]"):
        assert text in response.text
    if portal.kind == "srpm":
        for text in ("custom-csmock", "csmock --test", "test-mock", "gcc", "warning"):
            assert text in response.text
        assert_not_read(portal, "scan_finding")
        assert len(portal.statements) == 3
    else:
        for text in ("CVE-2026-0001", "visible description", "visible vector", "/usr/bin/demo",
                     "vendor", "product", "--update never"):
            assert text in response.text
        assert_not_read(portal, "scan_metadata", ".raw", ".comments")
        assert len(portal.statements) == 6
    assert_not_read(portal, "sync_error", "jenkins_url")


@pytest.mark.parametrize("endpoint", ["summary", "findings"])
@pytest.mark.parametrize("portal", ["srpm"], indirect=True)
def test_srpm_results_read_only_the_requested_collection(portal, endpoint):
    response = get(portal, f"/api/v1/srpm/tasks/{portal.id}/{endpoint}")
    assert response.status_code == 200
    rows = response.json() if endpoint == "summary" else response.json()["items"]
    assert len(rows) == 1
    if endpoint == "summary":
        assert rows == [{"checker": "gcc", "issue_type": "warning", "count": 1}]
        assert_not_read(portal, "scan_finding")
    else:
        assert rows[0]["message"] == "visible finding"
        assert rows[0]["raw"] == {"large": "x" * 20000}
        assert set(rows[0]) == {"id", "fingerprint", "checker", "rule_id", "severity",
                               "message", "file_path", "line", "column", "code_context", "raw"}
        assert_not_read(portal, "scan_summary")
    assert_not_read(portal, "scan_artifact", "scan_metadata", "sync_error")
    assert len(portal.statements) == (2 if endpoint == "summary" else 3)


@pytest.mark.parametrize("path", ["api", "web"])
def test_missing_task_reads_no_collections(portal, path):
    url = f"/api/v1/{portal.kind}/tasks/999999" if path == "api" else f"/{portal.kind}/999999"
    response = get(portal, url)
    assert response.status_code == 404
    assert len(portal.statements) == 1


@pytest.mark.parametrize("endpoint", ["summary", "findings"])
@pytest.mark.parametrize("portal", ["srpm"], indirect=True)
def test_missing_srpm_results_preserve_404(portal, endpoint):
    response = get(portal, f"/api/v1/srpm/tasks/999999/{endpoint}")
    assert response.status_code == 404
    assert len(portal.statements) == 1
