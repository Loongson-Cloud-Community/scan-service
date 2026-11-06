"""Completion acknowledgement must precede slow Jenkins I/O and parsing."""

import asyncio
from datetime import datetime
import json
from threading import Event

from fastapi import FastAPI
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from conftest import FakeJenkinsClient, RPM_SCAN_KEY, rpm_scan_artifacts, srpm_scan_artifacts
from scanservice import completion_sync, resync
from scanservice.db import Base, get_db
from scanservice.modules.rpm.api import routes as rpm_routes
from scanservice.modules.rpm.models import RpmScanTask
from scanservice.modules.rpm.services import events as rpm_events
from scanservice.modules.srpm.api import routes as srpm_routes
from scanservice.modules.srpm.models import SrpmScanTask
from scanservice.modules.srpm.services import events as srpm_events
from scanservice.security import require_ingest_token


@pytest.fixture(params=["rpm", "srpm"])
def callback(request, settings, monkeypatch):
    kind = request.param
    routes, module, model, state, exit_field = (
        (rpm_routes, rpm_events, RpmScanTask, "state", "cbt_exit_code") if kind == "rpm"
        else (srpm_routes, srpm_events, SrpmScanTask, "scan_result", "csmock_exit_code")
    )
    engine = create_engine("sqlite://", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    monkeypatch.setattr(completion_sync, "SessionLocal", factory)
    artifacts, contents = rpm_scan_artifacts() if kind == "rpm" else srpm_scan_artifacts()
    client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
    monkeypatch.setattr(module, "JenkinsClient", lambda *args, **kwargs: client)
    monkeypatch.setattr(routes, "get_settings", lambda: settings)
    app = FastAPI()
    app.include_router(routes.router)
    request_sessions = []

    def database():
        with factory() as db:
            request_sessions.append(db)
            yield db

    app.dependency_overrides[get_db] = database
    app.dependency_overrides[require_ingest_token] = lambda: None
    payload = {"event": "completed", "jenkins_job_full_name": "packages/curl",
               "jenkins_build_number": 7 if kind == "rpm" else 6,
               "finished_at": "2026-10-01T10:05:00+08:00", exit_field: 0}
    if kind == "rpm":
        payload.update(scan_key=RPM_SCAN_KEY, rpm_sha256=RPM_SCAN_KEY,
                       rpm_name="docker-24.0.9-8.lns23.loongarch64.rpm")
    else:
        payload["srpm_name"] = "curl-8.4.0-9.ocs23.src.rpm"
    try:
        yield kind, app, factory, client, model, state, payload, request_sessions
    finally:
        engine.dispose()


async def exchange(app, kind, payload, send):
    body = json.dumps(payload).encode()
    received = False
    disconnected = asyncio.Event()

    async def receive():
        nonlocal received
        if not received:
            received = True
            return {"type": "http.request", "body": body, "more_body": False}
        await disconnected.wait()
        return {"type": "http.disconnect"}

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
             "method": "POST", "scheme": "http", "path": f"/api/v1/{kind}/events",
             "raw_path": f"/api/v1/{kind}/events".encode(), "query_string": b"",
             "headers": [(b"content-type", b"application/json")],
             "server": ("portal", 80), "client": ("test", 1234), "root_path": ""}
    await app(scope, receive, send)


def test_response_is_sent_and_receipt_committed_before_jenkins_read(callback):
    kind, app, factory, client, model, state, payload, _ = callback
    sent = []
    acknowledged = Event()
    read = client.get_build

    def verify_receipt(job, number):
        assert acknowledged.is_set(), "Jenkins I/O started before acknowledgement"
        with factory() as db:
            task = db.scalars(select(model)).one()
            # SQLite drops timezone information; PostgreSQL is checked separately.
            assert task.finished_at == datetime(2026, 10, 1, 10, 5)
            assert task.sync_status == "PENDING"
        return read(job, number)

    client.get_build = verify_receipt

    async def send(message):
        sent.append(message)
        if message["type"] == "http.response.body" and not message.get("more_body", False):
            acknowledged.set()

    asyncio.run(exchange(app, kind, payload, send))
    assert sent[0]["status"] == 200
    ack = json.loads(b"".join(item.get("body", b"") for item in sent))
    assert ack["sync_status"] == "PENDING"
    assert ack[state] != "FINISHED"
    with factory() as db:
        task = db.scalars(select(model)).one()
        assert getattr(task, state) == "FINISHED"
        assert task.sync_status == "SYNCED"
    assert client.closed


def test_slow_sync_does_not_delay_response_body(callback):
    kind, app, _, client, _, _, payload, _ = callback
    entered, release = Event(), Event()
    read = client.get_build

    def slow_read(job, number):
        entered.set()
        assert release.wait(5), "test did not release its Jenkins stub"
        return read(job, number)

    client.get_build = slow_read

    async def verify():
        response_sent = asyncio.Event()

        async def send(message):
            if message["type"] == "http.response.body" and not message.get("more_body", False):
                response_sent.set()

        request = asyncio.create_task(exchange(app, kind, payload, send))
        try:
            await asyncio.wait_for(response_sent.wait(), 1)
            assert await asyncio.to_thread(entered.wait, 2)
            assert not request.done(), "synchronization should still be waiting on Jenkins"
        finally:
            release.set()
            await request

    asyncio.run(verify())


def test_background_uses_an_independent_database_session(callback, monkeypatch):
    kind, app, _, _, _, _, payload, request_sessions = callback
    routes = rpm_routes if kind == "rpm" else srpm_routes
    complete = routes.complete_task
    called = []

    def verify_session(db, settings, task):
        assert all(db is not request_db for request_db in request_sessions)
        called.append(task.id)
        return complete(db, settings, task)

    monkeypatch.setattr(routes, "complete_task", verify_session)

    async def send(message):
        pass

    asyncio.run(exchange(app, kind, payload, send))
    assert len(called) == 1


@pytest.mark.parametrize("interruption", ["jenkins_error", "background_not_run"])
def test_acknowledged_completion_remains_reconcilable(callback, monkeypatch, interruption):
    kind, app, factory, client, model, state, payload, _ = callback
    routes = rpm_routes if kind == "rpm" else srpm_routes
    read = client.get_build
    if interruption == "jenkins_error":
        def unavailable(*args):
            raise RuntimeError("Jenkins is unavailable")

        monkeypatch.setattr(client, "get_build", unavailable)
    else:
        # Model a process stopping after acknowledgement but before background work.
        monkeypatch.setattr(routes, "synchronize_completion", lambda *args: None)
    messages = []

    async def send(message):
        messages.append(message)

    asyncio.run(exchange(app, kind, payload, send))
    assert messages[0]["status"] == 200
    with factory() as db:
        task = db.scalars(select(model)).one()
        assert task.finished_at is not None
        assert getattr(task, state) != "FINISHED"
        assert task.sync_status == ("ERROR" if interruption == "jenkins_error" else "PENDING")
    monkeypatch.setattr(client, "get_build", read)
    monkeypatch.setattr(resync, "JenkinsClient", lambda *args, **kwargs: client)
    with factory() as db:
        result = routes.sync_tasks(db, None)
        assert result == {"attempted": 1, "synced": 1, "pending": 0, "failed": 0}
        task = db.scalars(select(model)).one()
        assert getattr(task, state) == "FINISHED"
        assert task.sync_status == "SYNCED"


def test_failed_receipt_commit_does_not_schedule_synchronization(callback, monkeypatch):
    kind, app, factory, client, model, _, payload, _ = callback

    class CommitFailureSession(factory.class_):
        def commit(self):
            raise RuntimeError("cannot commit receipt")

    failing_factory = sessionmaker(bind=factory.kw["bind"], class_=CommitFailureSession)

    def database():
        with failing_factory() as db:
            yield db

    app.dependency_overrides[get_db] = database
    sent = []

    async def send(message):
        sent.append(message)

    with pytest.raises(RuntimeError, match="cannot commit receipt"):
        asyncio.run(exchange(app, kind, payload, send))
    assert sent[0]["status"] == 500
    assert client.requested_builds == []
    with factory() as db:
        assert db.scalars(select(model)).all() == []


def test_background_skips_deleted_task(callback, settings):
    _, _, factory, _, model, _, _, _ = callback
    called = []
    completion_sync.synchronize_completion(
        settings, model, 999, lambda *args: called.append(True),
    )
    assert called == []


def test_background_handler_exception_is_logged_and_session_closed(callback, settings, monkeypatch, caplog):
    kind, app, factory, _, model, _, payload, _ = callback
    routes = rpm_routes if kind == "rpm" else srpm_routes
    monkeypatch.setattr(routes, "synchronize_completion", lambda *args: None)

    async def send(message):
        pass

    asyncio.run(exchange(app, kind, payload, send))
    with factory() as db:
        task_id = db.scalars(select(model.id)).one()
    closed = []

    class TrackedSession(factory.class_):
        def close(self):
            closed.append(True)
            super().close()

    monkeypatch.setattr(completion_sync, "SessionLocal", sessionmaker(
        bind=factory.kw["bind"], class_=TrackedSession,
    ))

    def broken_handler(db, settings, task):
        task.sync_error = "uncommitted mutation"
        db.flush()
        raise RuntimeError("unexpected processing failure")

    completion_sync.synchronize_completion(settings, model, task_id, broken_handler)
    assert closed == [True]
    assert "unexpected processing failure" in caplog.text
    with factory() as db:
        task = db.get(model, task_id)
        assert task.sync_status == "PENDING"
        assert task.sync_error is None
