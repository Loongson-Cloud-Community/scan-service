from __future__ import annotations

from collections import deque
from hmac import compare_digest
from threading import Lock
from time import monotonic

from fastapi import Header, HTTPException

from .config import get_settings


class _RateLimiter:
    def __init__(self) -> None:
        self._requests: deque[float] = deque()
        self._lock = Lock()

    def check(self, limit: int, window_seconds: float = 60.0) -> None:
        if limit < 1:
            raise HTTPException(status_code=503, detail="operator rate limit is invalid")
        now = monotonic()
        with self._lock:
            while self._requests and self._requests[0] <= now - window_seconds:
                self._requests.popleft()
            if len(self._requests) >= limit:
                retry_after = max(1, int(window_seconds - (now - self._requests[0])))
                raise HTTPException(
                    status_code=429,
                    detail="operator sync rate limit exceeded",
                    headers={"Retry-After": str(retry_after)},
                )
            self._requests.append(now)


_operator_sync_limiter = _RateLimiter()


def _require_bearer_token(
    authorization: str | None,
    expected_token: str,
    *,
    setting_name: str,
    token_name: str,
) -> None:
    if not expected_token:
        raise HTTPException(status_code=503, detail=f"{setting_name} is not configured")
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not compare_digest(token, expected_token):
        raise HTTPException(status_code=401, detail=f"invalid {token_name} token")


def require_ingest_token(
    authorization: str | None = Header(default=None),
) -> None:
    """Protect Jenkins-to-service callbacks without affecting read-only pages."""
    settings = get_settings()
    _require_bearer_token(
        authorization,
        settings.ingest_token,
        setting_name="SCAN_SERVICE_INGEST_TOKEN",
        token_name="ingest",
    )


def require_operator_token(
    authorization: str | None = Header(default=None),
) -> None:
    """Protect synchronization operations while public reads stay anonymous."""
    settings = get_settings()
    _require_bearer_token(
        authorization,
        settings.operator_token,
        setting_name="SCAN_SERVICE_OPERATOR_TOKEN",
        token_name="operator",
    )
    _operator_sync_limiter.check(settings.operator_sync_rate_limit)
