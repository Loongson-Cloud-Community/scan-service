"""Shared browser policy for direct artifacts and archive members.

Known text and image formats can be viewed inline; unknown formats are
downloaded. Text-like scan artifacts are served as ``text/plain`` when viewed
so JSON, CSV and log files remain readable. Active documents share a sandbox
that allows report scripts without inheriting the Portal's origin.
"""

from __future__ import annotations

import mimetypes
from pathlib import PurePosixPath
from typing import TypedDict


# Artifact types rendered as plain text for the "view" link. ``attachment``
# downloads keep their original media type.
VIEWABLE_TEXT_ARTIFACT_TYPES = frozenset(
    {
        "METADATA",
        "REPORT_JSON",
        "REPORT_CSV",
        "LOG",
        "SUMMARY",
    }
)


ACTIVE_MEDIA_TYPES = {
    ".html": "text/html",
    ".htm": "text/html",
    ".xhtml": "application/xhtml+xml",
    ".xht": "application/xhtml+xml",
    ".svg": "image/svg+xml",
}
INLINE_MEDIA_TYPES = frozenset(ACTIVE_MEDIA_TYPES.values()) | {
    "text/plain",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/bmp",
    "image/x-icon",
}
REPORT_SANDBOX = (
    "sandbox allow-scripts; "
    "default-src 'none'; "
    "script-src 'unsafe-inline'; "
    "style-src 'unsafe-inline'; "
    "img-src data: blob:; "
    "connect-src 'none'"
)


class _ResponseOptions(TypedDict):
    media_type: str
    headers: dict[str, str]


def _artifact_media_type(*, artifact_type: str, filename: str, download: bool) -> str:
    if not download and artifact_type in VIEWABLE_TEXT_ARTIFACT_TYPES:
        return "text/plain"
    # Keep active formats explicit instead of relying on the host MIME database.
    return (
        ACTIVE_MEDIA_TYPES.get(PurePosixPath(filename).suffix.lower())
        or mimetypes.guess_type(filename)[0]
        or "application/octet-stream"
    )


def artifact_response_options(
    *, artifact_type: str, filename: str, download: bool
) -> _ResponseOptions:
    media_type = _artifact_media_type(
        artifact_type=artifact_type, filename=filename, download=download
    )
    inline = not download and media_type in INLINE_MEDIA_TYPES
    disposition = "inline" if inline else "attachment"
    filename = filename.replace('"', "'")
    headers = {
        "Content-Disposition": f'{disposition}; filename="{filename}"',
        "X-Content-Type-Options": "nosniff",
    }
    if inline and media_type in ACTIVE_MEDIA_TYPES.values():
        # Reports need inline JS for search/charts, but must not inherit the
        # Portal's origin or make network requests. Do not add allow-same-origin.
        headers["Content-Security-Policy"] = REPORT_SANDBOX
    return {"media_type": media_type, "headers": headers}
