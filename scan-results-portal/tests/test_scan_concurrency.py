"""PostgreSQL-only regression tests, using an isolated temporary schema."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from conftest import RPM_SCAN_KEY, FakeJenkinsClient, rpm_scan_artifacts, srpm_scan_artifacts
from scanservice import completion_sync, resync as resync_module
from scanservice.modules.rpm.models import RpmScanTask
from scanservice.modules.rpm.services import events as rpm_events
from scanservice.modules.rpm.services.synchronization import sync_task
from scanservice.modules.srpm.models import SrpmScanTask
from scanservice.modules.srpm.services import events as srpm_events
from scanservice.modules.srpm.services.synchronization import sync_build
from scanservice.scan_protocol import ScanIdentityConflict


STARTED = datetime(2026, 10, 1, 10, tzinfo=timezone.utc)
FINISHED = datetime(2026, 10, 1, 11, tzinfo=timezone.utc)


@pytest.fixture(params=["rpm", "srpm"])
def scan_type(request, settings, monkeypatch):
    kind = request.param
    values = {
        "jenkins_job_full_name": "packages/curl", "jenkins_build_number": 6,
        "created_at": STARTED,
    }
    if kind == "rpm":
        model, module, state_field = RpmScanTask, rpm_events, "state"
        values.update(scan_key=RPM_SCAN_KEY, rpm_sha256=RPM_SCAN_KEY,
                      rpm_name="docker-24.0.9-8.lns23.loongarch64.rpm")
        artifacts, contents = rpm_scan_artifacts(prefix=f"rpm-scan-artifacts/6/{RPM_SCAN_KEY}")
    else:
        model, module, state_field = SrpmScanTask, srpm_events, "scan_result"
        values["srpm_name"] = "curl-8.4.0-9.ocs23.src.rpm"
        artifacts, contents = srpm_scan_artifacts()

    def start(db, **overrides):
        incoming = {**values, **overrides}
        if kind == "rpm":
            return module.register_start(db, incoming)
        return module.register_start(db, settings, incoming)

    def fail(db, task):
        if kind == "rpm":
            return module.fail_task(db, task, {"finished_at": FINISHED, "cbt_exit_code": 2})
        return module.fail_task(db, settings, task, FINISHED, 2)

    def complete(db, task):
        if kind == "rpm":
            return module.complete_task(db, settings, task, {
                **values, "finished_at": FINISHED, "cbt_exit_code": 0,
            })
        return module.complete_task(db, settings, task, FINISHED, 0)

    def sync(db, task):
        client = FakeJenkinsClient(artifacts=artifacts, contents=contents)
        if kind == "rpm":
            return sync_task(db, client, task)
        return sync_build(db, client, settings, 6, values["jenkins_job_full_name"])

    monkeypatch.setattr(module, "JenkinsClient", lambda *args, **kwargs: FakeJenkinsClient(
        artifacts=artifacts, contents=contents,
    ))
    return kind, model, state_field, start, fail, complete, sync


def test_concurrent_first_registration_reuses_one_task(pg_engine, scan_type):
    _, model, _, start, *_ = scan_type
    barrier = Barrier(2)

    def simultaneous_insert(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("INSERT INTO") and model.__tablename__ in statement:
            barrier.wait(timeout=10)

    event.listen(pg_engine, "before_cursor_execute", simultaneous_insert)
    try:
        def register():
            with Session(pg_engine, autoflush=False, expire_on_commit=False) as db:
                task = start(db)
                db.commit()
                return task.id

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = [future.result(timeout=15) for future in [pool.submit(register), pool.submit(register)]]
    finally:
        event.remove(pg_engine, "before_cursor_execute", simultaneous_insert)

    assert results[0] == results[1]
    with Session(pg_engine) as db:
        task = db.scalars(select(model)).one()
        assert task.created_at == STARTED


@pytest.mark.parametrize("later", ["started", "completed", "failed", "sync"])
@pytest.mark.parametrize("terminal", ["FAILED", "FINISHED"])
def test_stale_task_cannot_overwrite_a_committed_terminal_decision(pg_engine, scan_type, later, terminal):
    _, model, state_field, start, fail, complete, sync = scan_type
    with Session(pg_engine, expire_on_commit=False) as seed:
        task = start(seed)
        seed.flush()
        task_id = task.id
        seed.commit()

    with Session(pg_engine, autoflush=False, expire_on_commit=False) as stale:
        old = stale.get(model, task_id)
        assert getattr(old, state_field) == "RUNNING"
        with Session(pg_engine, autoflush=False) as winner:
            current = winner.get(model, task_id)
            if terminal == "FAILED":
                fail(winner, current)
            else:
                complete(winner, current)
            winner.commit()

        if later == "started":
            start(stale)
        elif later == "completed":
            complete(stale, old)
        elif later == "failed":
            fail(stale, old)
        else:
            sync(stale, old)
        stale.commit()
        assert getattr(old, state_field) == terminal
        assert old.finished_at == FINISHED
        assert getattr(old, "cbt_exit_code" if model is RpmScanTask else "csmock_exit_code") == (
            2 if terminal == "FAILED" else 0
        )


def test_concurrent_conflicting_registration_preserves_the_winner(pg_engine, scan_type):
    kind, model, _, start, *_ = scan_type
    field = "rpm_name" if kind == "rpm" else "srpm_name"
    barrier = Barrier(2)

    def simultaneous_insert(connection, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("INSERT INTO") and model.__tablename__ in statement:
            barrier.wait(timeout=10)

    def register(name):
        with Session(pg_engine, autoflush=False, expire_on_commit=False) as db:
            try:
                task = start(db, **{field: name})
                db.commit()
                return "accepted", name, task.id
            except ScanIdentityConflict:
                db.rollback()
                return "conflict", name, None

    event.listen(pg_engine, "before_cursor_execute", simultaneous_insert)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(register, name) for name in ("first.src.rpm", "second.src.rpm")]
            results = [future.result(timeout=15) for future in futures]
    finally:
        event.remove(pg_engine, "before_cursor_execute", simultaneous_insert)
    accepted = [row for row in results if row[0] == "accepted"]
    assert len(accepted) == 1
    assert [row[0] for row in results].count("conflict") == 1
    with Session(pg_engine) as db:
        task = db.scalars(select(model)).one()
        assert getattr(task, field) == accepted[0][1]


def test_lock_is_per_task_and_retained_until_commit(pg_engine, scan_type):
    _, model, state_field, start, fail, *_ = scan_type
    with Session(pg_engine) as seed:
        task = start(seed)
        task_id = task.id
        seed.commit()

    with Session(pg_engine) as holder, Session(pg_engine) as other:
        task = holder.get(model, task_id)
        fail(holder, task)
        other.execute(text("SET LOCAL lock_timeout = '250ms'"))
        with pytest.raises(OperationalError) as exc_info:
            start(other)
        assert exc_info.value.orig.sqlstate == "55P03"
        other.rollback()

        other.execute(text("SET LOCAL lock_timeout = '250ms'"))
        independent = start(other, jenkins_job_full_name="packages/other")
        other.commit()
        assert independent.id != task_id
        holder.commit()

        retried = start(other)
        other.commit()
        assert getattr(retried, state_field) == "FAILED"


def test_concurrent_completion_does_not_duplicate_results(pg_engine, scan_type):
    kind, model, state_field, start, _, complete, _ = scan_type
    with Session(pg_engine) as seed:
        task = start(seed)
        task_id = task.id
        seed.commit()
    barrier = Barrier(2)

    def finish():
        with Session(pg_engine, autoflush=False, expire_on_commit=False) as db:
            stale = db.get(model, task_id)
            barrier.wait(timeout=10)
            task = complete(db, stale)
            db.commit()
            return getattr(task, state_field)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = [future.result(timeout=15) for future in [pool.submit(finish), pool.submit(finish)]]
    assert results == ["FINISHED", "FINISHED"]
    with Session(pg_engine) as db:
        task = db.get(model, task_id)
        assert len(task.artifacts) == (5 if kind == "rpm" else 7)
        assert len(task.vulnerabilities if kind == "rpm" else task.summaries) == (2 if kind == "rpm" else 1)


def test_resync_error_does_not_damage_another_requests_terminal_result(
    pg_engine, scan_type, settings, monkeypatch,
):
    _, model, state_field, start, fail, *_ = scan_type
    with Session(pg_engine) as seed:
        task_id = start(seed).id
        seed.commit()
    monkeypatch.setattr(resync_module, "JenkinsClient", lambda *args, **kwargs: FakeJenkinsClient())

    def delayed_failure(db, client, settings, task):
        with Session(pg_engine) as winner:
            fail(winner, winner.get(model, task_id))
            winner.commit()
        raise RuntimeError("late synchronization error")

    with Session(pg_engine) as db:
        result = resync_module.resync_registered_tasks(
            settings, db, model=model, state_column=getattr(model, state_field),
            active_states=("RUNNING", "NOT_AVAILABLE"), sync_one=delayed_failure,
        )
        assert result == {"attempted": 1, "synced": 0, "pending": 0, "failed": 1}
        task = db.get(model, task_id)
        assert getattr(task, state_field) == "FAILED"
        assert task.sync_status == "SYNCED"
        assert task.sync_error is None


@pytest.mark.parametrize("fail_attempt", [False, True])
def test_resync_rotates_durable_attempts_on_postgresql(
    pg_engine, scan_type, settings, monkeypatch, fail_attempt,
):
    _, model, state_field, start, *_ = scan_type
    with Session(pg_engine) as seed:
        for number in range(1, 4):
            task = start(seed, jenkins_build_number=number)
            task.created_at_service = STARTED + timedelta(hours=number)
            if number == 1:
                task.last_synced_at = STARTED + timedelta(hours=1, minutes=30)
        seed.commit()
    monkeypatch.setattr(resync_module, "JenkinsClient", lambda *args, **kwargs: FakeJenkinsClient())
    seen = []

    def attempt(db, client, settings, task):
        seen.append(task.jenkins_build_number)
        if fail_attempt:
            raise RuntimeError("temporary Jenkins failure")

    for _ in range(3):
        # Reopening the session proves rotation is persisted, not process-local.
        with Session(pg_engine) as db:
            result = resync_module.resync_registered_tasks(
                replace(settings, recent_build_limit=1), db,
                model=model, state_column=getattr(model, state_field),
                active_states=("RUNNING", "NOT_AVAILABLE"), sync_one=attempt,
            )
            assert result == {
                "attempted": 1, "synced": 0,
                "pending": 0 if fail_attempt else 1, "failed": int(fail_attempt),
            }
    assert seen == [1, 2, 3]


@pytest.mark.parametrize("terminal", [None, "FAILED", "FINISHED"])
def test_completion_background_reads_committed_receipt_and_preserves_terminal_state(
    pg_engine, scan_type, settings, monkeypatch, terminal,
):
    kind, model, state_field, start, fail, complete, _ = scan_type
    module = rpm_events if kind == "rpm" else srpm_events
    factory = sessionmaker(bind=pg_engine, autoflush=False, expire_on_commit=False)
    monkeypatch.setattr(completion_sync, "SessionLocal", factory)
    with factory() as request:
        task = start(request)
        if kind == "rpm":
            module.record_completion(request, task, {"finished_at": FINISHED, "cbt_exit_code": 0})
        else:
            module.record_completion(request, task, FINISHED, 0)
        task_id = task.id
        request.commit()
        # A different request may establish a terminal result before work starts.
        if terminal:
            with factory() as winner:
                current = winner.get(model, task_id)
                (fail if terminal == "FAILED" else complete)(winner, current)
                winner.commit()

            def unexpected_client(*args, **kwargs):
                pytest.fail("terminal completion must not contact Jenkins again")

            monkeypatch.setattr(module, "JenkinsClient", unexpected_client)
        processed = []

        def handle(background_db, background_settings, current):
            assert background_db is not request
            assert current.finished_at == FINISHED
            if not terminal:
                assert current.sync_status == "PENDING"
            processed.append(current.id)
            return complete(background_db, current)

        completion_sync.synchronize_completion(settings, model, task_id, handle)
        assert processed == [task_id]
    with factory() as db:
        current = db.get(model, task_id)
        assert getattr(current, state_field) == (terminal or "FINISHED")
        assert current.sync_status == "SYNCED"
        assert current.finished_at == FINISHED
