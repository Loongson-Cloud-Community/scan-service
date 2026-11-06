from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from scanservice.config import ArtifactLimits
from scanservice.jenkins import JenkinsClient
from scanservice.modules.rpm.services import artifacts as rpm_artifacts
from scanservice.modules.srpm.services import artifacts as srpm_artifacts


class TrackedStream(httpx.SyncByteStream):
    def __init__(self, chunks, error=None):
        self.chunks = chunks
        self.error = error
        self.yielded = 0
        self.closed = False

    def __iter__(self):
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk
        if self.error:
            raise self.error

    def close(self):
        self.closed = True


@pytest.fixture(params=[rpm_artifacts, srpm_artifacts], ids=["rpm", "srpm"])
def delivery(request, monkeypatch, settings):
    module = request.param
    clients = []
    monkeypatch.setattr(
        module, "get_settings",
        lambda: replace(settings, artifact_limits=ArtifactLimits(max_download_bytes=4)),
    )
    task = SimpleNamespace(jenkins_job_full_name="demo", jenkins_build_number=1)
    artifact = SimpleNamespace(
        name="scan.log", relative_path="scan.log", artifact_type="LOG", size_bytes=None
    )

    def prepare(stream, status=200, headers=None, request_error=None):
        client = JenkinsClient("http://jenkins")
        client.client.close()

        def handler(request):
            if request_error:
                raise request_error
            return httpx.Response(status, headers=headers, stream=stream, request=request)

        client.client = httpx.Client(transport=httpx.MockTransport(handler))
        clients.append(client)
        monkeypatch.setattr(module, "JenkinsClient", lambda *args, **kwargs: client)
        return client

    yield SimpleNamespace(
        module=module, task=task, artifact=artifact, prepare=prepare, settings=settings
    )
    for client in clients:
        client.close()


def get_response(delivery):
    return delivery.module.artifact_response(
        delivery.task, delivery.artifact, download=True
    )


async def request_artifact(delivery):
    app = FastAPI()

    @app.get("/artifact")
    def download():
        return get_response(delivery)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://portal",
    ) as client:
        return await client.get("/artifact")


@pytest.mark.parametrize(
    ("status", "headers", "request_error", "expected_status"),
    [
        (404, None, None, 404),
        (500, None, None, 502),
        (200, {"Content-Length": "20"}, None, 413),
        (200, {"Content-Length": "invalid"}, None, 502),
        (200, None, httpx.ConnectError("internal address"), 502),
    ],
)
def test_upstream_rejection_is_reported_before_http_success(
    delivery, status, headers, request_error, expected_status
):
    stream = TrackedStream([b"ok"])
    client = delivery.prepare(stream, status, headers, request_error)

    response = asyncio.run(request_artifact(delivery))

    assert response.status_code == expected_status
    assert "internal address" not in response.text
    assert client.client.is_closed
    if request_error is None:
        assert stream.closed


@pytest.mark.parametrize("error", [httpx.ReadTimeout("internal address"), None])
def test_first_read_failure_is_reported_before_http_success(delivery, error):
    stream = TrackedStream([] if error else [b"too large"], error=error)
    client = delivery.prepare(stream)

    response = asyncio.run(request_artifact(delivery))

    assert response.status_code == (502 if error else 413)
    assert "internal address" not in response.text
    assert stream.closed and client.client.is_closed


@pytest.mark.parametrize("payload", [b"", b"okay"])
def test_empty_and_nonempty_downloads_close_upstream(delivery, payload):
    stream = TrackedStream([payload] if payload else [])
    client = delivery.prepare(stream)

    response = asyncio.run(request_artifact(delivery))

    assert response.status_code == 200
    assert response.content == payload
    assert response.headers["content-disposition"] == 'attachment; filename="scan.log"'
    assert stream.closed and client.client.is_closed


def test_disconnect_closes_upstream_without_consuming_the_rest(delivery, monkeypatch):
    monkeypatch.setattr(delivery.module, "get_settings", lambda: delivery.settings)
    stream = TrackedStream([b"a" * 65536, b"b" * 65536])
    client = delivery.prepare(stream)
    response = get_response(delivery)
    assert stream.yielded == 1

    async def disconnect():
        disconnected = asyncio.Event()

        async def receive():
            await disconnected.wait()
            return {"type": "http.disconnect"}

        async def send(message):
            if message["type"] == "http.response.body":
                disconnected.set()
                await asyncio.Event().wait()

        await response({"type": "http"}, receive, send)

    asyncio.run(disconnect())

    assert stream.yielded == 1
    assert stream.closed and client.client.is_closed


def test_failure_before_body_iteration_still_closes_upstream(delivery):
    stream = TrackedStream([b"okay"])
    client = delivery.prepare(stream)
    response = get_response(delivery)

    async def fail_send():
        async def receive():
            await asyncio.Event().wait()

        async def send(message):
            raise RuntimeError("client connection failed")

        await response({"type": "http"}, receive, send)

    with pytest.raises(Exception):
        asyncio.run(fail_send())

    assert stream.closed and client.client.is_closed


@pytest.mark.parametrize("failure", ["network", "size"])
def test_midstream_failure_closes_upstream_without_successful_end(
    delivery, monkeypatch, failure
):
    stream = TrackedStream(
        [b"a" * 65536] if failure == "network" else [b"a" * 65536, b"b"],
        error=httpx.ReadError("upstream failed") if failure == "network" else None,
    )
    client = delivery.prepare(stream)
    # Let the first chunk through so this is a genuine post-header failure.
    monkeypatch.setattr(
        delivery.module, "get_settings",
        lambda: replace(
            delivery.settings,
            artifact_limits=ArtifactLimits(max_download_bytes=65536),
        ),
    )
    response = get_response(delivery)
    messages = []

    async def consume():
        async def receive():
            await asyncio.Event().wait()

        async def send(message):
            messages.append(message)

        await response({"type": "http"}, receive, send)

    with pytest.raises(Exception):
        asyncio.run(consume())

    assert messages[0]["status"] == 200
    assert not any(
        message["type"] == "http.response.body" and not message["more_body"]
        for message in messages
    )
    assert stream.closed and client.client.is_closed
