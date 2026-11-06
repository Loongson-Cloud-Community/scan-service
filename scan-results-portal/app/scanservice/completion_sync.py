"""Process an accepted completion after the HTTP response, in its own session."""

from __future__ import annotations

import logging
from typing import Any, Callable

from sqlalchemy.orm import Session

from .config import Settings
from .db import SessionLocal


logger = logging.getLogger(__name__)
CompletionHandler = Callable[[Session, Settings, Any], Any]


def synchronize_completion(
    settings: Settings,
    model: type[Any],
    task_id: int,
    complete: CompletionHandler,
) -> None:
    # Pass identity only, never the request session or an attached ORM object.
    # The event is already committed. If this process stops before handling it,
    # the registered task remains eligible for the existing reconciliation API.
    try:
        with SessionLocal() as db:
            task = db.get(model, task_id)
            if task is not None:
                complete(db, settings, task)
    except Exception:
        # Recovery can itself fail (for example if PostgreSQL is unavailable).
        # Do not turn a committed acknowledgement into a response-time error.
        logger.exception(
            "Unable to process accepted completion: task_type=%s task_id=%s",
            model.__tablename__, task_id,
        )
