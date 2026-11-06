"""Verify reconciliation counts through both authenticated HTTP interfaces."""

import asyncio

from fastapi import FastAPI
import httpx
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from conftest import FakeJenkinsClient, RPM_SCAN_KEY, rpm_scan_artifacts, srpm_scan_artifacts
from scanservice import resync, security
from scanservice.db import Base, get_db
from scanservice.modules.rpm.api import routes as rpm_routes
from scanservice.modules.rpm.models import RpmScanTask
from scanservice.modules.srpm.api import routes as srpm_routes
from scanservice.modules.srpm.models import SrpmScanTask


@pytest.mark.parametrize("kind", ["rpm", "srpm"])
def test_sync_http_counts_valid_pending_missing_and_unreachable_builds(kind, settings, monkeypatch):
    routes, model, state_field = (
        (rpm_routes, RpmScanTask, "state") if kind == "rpm"
        else (srpm_routes, SrpmScanTask, "scan_result")
    )
    build_number = 7 if kind == "rpm" else 6
    artifacts, contents = rpm_scan_artifacts() if kind == "rpm" else srpm_scan_artifacts()
    backends = {
        "finished": FakeJenkinsClient(artifacts=artifacts, contents=contents),
        "pending": FakeJenkinsClient(building=True),
        "missing": FakeJenkinsClient(),
    }

    class Jenkins(FakeJenkinsClient):
        def get_build(self, job, number):
            if job == "unreachable":
                raise RuntimeError("Jenkins build is unreachable")
            return backends[job].get_build(job, number)

        def get_artifact(self, job, number, path, **kwargs):
            return backends[job].get_artifact(job, number, path, **kwargs)

    client = Jenkins()
    monkeypatch.setattr(resync, "JenkinsClient", lambda *args, **kwargs: client)
    monkeypatch.setattr(routes, "get_settings", lambda: settings)
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    monkeypatch.setattr(security, "_operator_sync_limiter", security._RateLimiter())
    engine = create_engine(
        "sqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as seed:
            for job in ("finished", "pending", "missing", "unreachable"):
                values = {"jenkins_job_full_name": job, "jenkins_build_number": build_number,
                          state_field: "RUNNING", "sync_status": "PENDING"}
                if kind == "rpm":
                    values.update(scan_key=RPM_SCAN_KEY, rpm_sha256=RPM_SCAN_KEY,
                                  rpm_name="docker-24.0.9-8.lns23.loongarch64.rpm")
                seed.add(model(**values))
            seed.commit()

        def database():
            with Session(engine) as db:
                yield db

        app = FastAPI()
        app.include_router(routes.router)
        app.dependency_overrides[get_db] = database

        async def request():
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="http://portal",
            ) as browser:
                denied = await browser.post(f"/api/v1/{kind}/sync")
                assert denied.status_code == 401
                return await browser.post(
                    f"/api/v1/{kind}/sync", headers={"Authorization": "Bearer operator"},
                )

        response = asyncio.run(request())
        assert response.status_code == 200
        assert response.json() == {"attempted": 4, "synced": 1, "pending": 1, "failed": 2}
        assert client.closed
        with Session(engine) as db:
            states = {row.jenkins_job_full_name: getattr(row, state_field)
                      for row in db.scalars(select(model))}
            assert states == {"finished": "FINISHED", "pending": "RUNNING",
                              "missing": "NOT_AVAILABLE", "unreachable": "RUNNING"}
    finally:
        engine.dispose()
