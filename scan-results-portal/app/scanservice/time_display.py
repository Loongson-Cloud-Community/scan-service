"""Shared page-time formatting; event and persistence timestamps stay unchanged."""

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from jinja2 import pass_context
from jinja2.runtime import Context


def format_timestamp(value: datetime | None, timezone_name: str) -> str:
    if value is None:
        return "—"
    if value.tzinfo is None or value.utcoffset() is None:
        # Internal legacy UTC timestamps and SQLite reads can be naive. Never
        # interpret them using the container's local timezone.
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(ZoneInfo(timezone_name)).strftime("%Y-%m-%d %H:%M:%S")


@pass_context
def timestamp_filter(context: Context, value: datetime | None) -> str:
    return format_timestamp(value, context["display_timezone"])
