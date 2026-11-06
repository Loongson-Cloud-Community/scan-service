"""Serialize scan-task writes using the database's existing unique keys."""

from typing import Any, TypeVar

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session


Task = TypeVar("Task")


def find_locked_task(db: Session, model: type[Task], identity: dict[str, Any]) -> Task | None:
    return db.scalar(
        select(model)
        .where(*(getattr(model, key) == value for key, value in identity.items()))
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def ensure_locked_task(
    db: Session, model: type[Task], identity: dict[str, Any], defaults: dict[str, Any],
) -> Task:
    task = find_locked_task(db, model, identity)
    if task is None:
        # The unique constraint arbitrates even when both requests saw no row.
        # A losing insert waits for the winner, without aborting its transaction.
        dialect = db.get_bind().dialect.name
        if dialect == "postgresql":
            insert = pg_insert
        elif dialect == "sqlite":
            insert = sqlite_insert  # Unit tests only; production uses PostgreSQL.
        else:
            raise ValueError(f"unsupported scan-task database: {dialect}")
        db.execute(
            insert(model).values(**defaults, **identity).on_conflict_do_nothing(
                index_elements=list(identity),
            )
        )
        task = find_locked_task(db, model, identity)
    if task is None:
        raise RuntimeError("scan task disappeared during registration")
    return task


def lock_task(db: Session, task: Task) -> None:
    """Reload state under a row lock before making a write decision.

    PostgreSQL retains the lock until commit/rollback, including result sync.
    SQLite unit tests do not provide these row-locking guarantees.
    """
    if db.get_bind().dialect.name == "postgresql":
        db.refresh(task, with_for_update=True)
