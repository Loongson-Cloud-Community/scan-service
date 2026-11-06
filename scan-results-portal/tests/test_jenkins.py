from __future__ import annotations

import httpx
import pytest

from scanservice.jenkins import JenkinsArtifactTooLarge, JenkinsClient


def _client_with_payload(payload: bytes) -> JenkinsClient:
    client = JenkinsClient("http://jenkins")
    client.client.close()
    client.client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, content=payload, request=request)
        )
    )
    return client


def test_artifact_reader_enforces_content_length_limit():
    client = _client_with_payload(b"0123456789")
    try:
        with pytest.raises(JenkinsArtifactTooLarge):
            client.get_artifact("job", 1, "result.json", max_bytes=5)
    finally:
        client.close()


def test_artifact_reader_streams_bounded_chunks():
    client = _client_with_payload(b"0123456789")
    try:
        chunks = list(
            client.iter_artifact(
                "job",
                1,
                "result.json",
                max_bytes=10,
                chunk_size=4,
            )
        )
    finally:
        client.close()

    assert chunks == [b"0123", b"4567", b"89"]
