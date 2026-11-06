from __future__ import annotations

import pytest
from fastapi import HTTPException

from scanservice import security


def test_operator_token_is_required(monkeypatch, settings):
    monkeypatch.setattr(security, "get_settings", lambda: settings)

    with pytest.raises(HTTPException) as exc_info:
        security.require_operator_token(None)

    assert exc_info.value.status_code == 401


def test_operator_token_accepts_configured_bearer(monkeypatch, settings):
    monkeypatch.setattr(security, "get_settings", lambda: settings)
    security._operator_sync_limiter._requests.clear()

    security.require_operator_token("Bearer operator")


def test_operator_sync_is_rate_limited(monkeypatch, settings):
    limited_settings = settings.__class__(
        **{**settings.__dict__, "operator_sync_rate_limit": 1}
    )
    monkeypatch.setattr(security, "get_settings", lambda: limited_settings)
    security._operator_sync_limiter._requests.clear()

    security.require_operator_token("Bearer operator")
    with pytest.raises(HTTPException) as exc_info:
        security.require_operator_token("Bearer operator")

    assert exc_info.value.status_code == 429
    security._operator_sync_limiter._requests.clear()
