"""Validate an upstream artifact before HTTP success and own its lifetime."""

from __future__ import annotations

from collections.abc import Callable, Iterator
import logging

import anyio
import httpx
from fastapi import HTTPException
from fastapi.responses import Response, StreamingResponse
from starlette.concurrency import run_in_threadpool
from starlette.types import Receive, Scope, Send

from .artifact_policy import artifact_response_options
from .jenkins import (
    JenkinsArtifactNotFound,
    JenkinsArtifactTooLarge,
    JenkinsClient,
    JenkinsError,
)


logger = logging.getLogger(__name__)


class _ArtifactStreamingResponse(StreamingResponse):
    def __init__(
        self,
        content: Iterator[bytes],
        close_stream: Callable[[], None],
        *,
        media_type: str,
        headers: dict[str, str],
    ) -> None:
        super().__init__(content, media_type=media_type, headers=headers)
        self._close_stream = close_stream

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        try:
            await super().__call__(scope, receive, send)
        finally:
            # Starlette does not guarantee that a suspended sync generator is
            # closed on disconnect or send failure. Cleanup must also survive
            # cancellation and a failure before body iteration has started.
            with anyio.CancelScope(shield=True):
                await run_in_threadpool(self._close_stream)


def artifact_stream_response(
    client: JenkinsClient,
    chunks: Iterator[bytes],
    *,
    artifact_type: str,
    filename: str,
    download: bool,
) -> Response:
    closed = False

    def close_stream() -> None:
        nonlocal closed
        if closed:
            return
        closed = True
        try:
            close_iterator = getattr(chunks, "close", None)
            if close_iterator is not None:
                close_iterator()
        finally:
            client.close()

    try:
        options = artifact_response_options(
            artifact_type=artifact_type, filename=filename, download=download
        )
        # Reading one bounded chunk runs Jenkins status/length checks before
        # StreamingResponse sends HTTP 200. The rest stays lazy and bounded.
        first = next(chunks, None)
        if first is None:
            close_stream()
            return Response(content=b"", **options)

        def body() -> Iterator[bytes]:
            try:
                yield first
                yield from chunks
            except (JenkinsError, httpx.HTTPError):
                # Headers have already been sent: propagate the error rather
                # than ending the response as a successful complete download.
                logger.exception("Artifact stream failed after response started")
                raise
            finally:
                close_stream()

        return _ArtifactStreamingResponse(body(), close_stream, **options)
    except JenkinsArtifactTooLarge as exc:
        close_stream()
        raise HTTPException(status_code=413, detail="artifact is too large to serve") from exc
    except JenkinsArtifactNotFound as exc:
        close_stream()
        raise HTTPException(status_code=404, detail="artifact not found") from exc
    except (JenkinsError, httpx.HTTPError, ValueError) as exc:
        close_stream()
        raise HTTPException(status_code=502, detail="unable to read artifact") from exc
    except BaseException:
        close_stream()
        raise
