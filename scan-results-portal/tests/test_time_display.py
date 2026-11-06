"""Display zones must not depend on container time or rewrite stored instants."""

from dataclasses import replace
from datetime import datetime
import time

from jinja2 import Environment
import pytest

from scanservice.config import Settings
from scanservice.modules.rpm.web import routes as rpm_web
from scanservice.modules.srpm.web import routes as srpm_web
from scanservice.time_display import format_timestamp, timestamp_filter


@pytest.mark.parametrize("source,zone,expected", [
    ("2026-11-06T08:03:50+00:00", "Asia/Shanghai", "2026-11-06 16:03:50"),
    ("2026-11-06T16:03:50+08:00", "Asia/Shanghai", "2026-11-06 16:03:50"),
    ("2026-11-06T03:03:50-05:00", "Asia/Shanghai", "2026-11-06 16:03:50"),
    ("2026-11-06T23:59:59.123456+00:00", "Asia/Shanghai", "2026-11-07 07:59:59"),
    ("2026-11-06T16:03:50+08:00", "UTC", "2026-11-06 08:03:50"),
    ("2026-03-08T06:59:59+00:00", "America/New_York", "2026-03-08 01:59:59"),
    ("2026-03-08T07:00:00+00:00", "America/New_York", "2026-03-08 03:00:00"),
])
def test_formatting_converts_the_instant_without_mutating_input(source, zone, expected):
    value = datetime.fromisoformat(source)
    assert format_timestamp(value, zone) == expected
    assert value.isoformat() == source


@pytest.mark.parametrize("system_zone", ["UTC", "Asia/Shanghai", "America/New_York"])
def test_naive_internal_utc_values_do_not_use_container_timezone(monkeypatch, system_zone):
    value = datetime(2026, 11, 6, 8, 3, 50)
    try:
        with monkeypatch.context() as state:
            state.setenv("TZ", system_zone)
            time.tzset()
            assert format_timestamp(value, "Asia/Shanghai") == "2026-11-06 16:03:50"
            assert value.tzinfo is None
    finally:
        time.tzset()


def test_missing_time_keeps_the_existing_placeholder():
    assert format_timestamp(None, "Asia/Shanghai") == "—"


def test_both_modules_use_one_context_aware_filter():
    for web in (rpm_web, srpm_web):
        assert web.templates.env.filters["timestamp"] is timestamp_filter
    env = Environment()
    env.filters["timestamp"] = timestamp_filter
    template = env.from_string("{{ value|timestamp }}")
    value = datetime.fromisoformat("2026-11-06T08:03:50+00:00")
    assert template.render(value=value, display_timezone="UTC") == "2026-11-06 08:03:50"
    assert template.render(value=value, display_timezone="Asia/Shanghai") == "2026-11-06 16:03:50"


@pytest.mark.parametrize("zone", ["Asia/Shanghai", "UTC", "America/New_York"])
def test_settings_load_ui_timezone_from_yaml(tmp_path, monkeypatch, zone):
    config = tmp_path / "config.yaml"
    config.write_text(f"ui:\n  timezone: {zone}\n", encoding="utf-8")
    monkeypatch.setenv("SCAN_SERVICE_CONFIG", str(config))
    assert Settings.from_environment().timezone == zone


def test_missing_ui_timezone_defaults_to_shanghai(tmp_path, monkeypatch):
    config = tmp_path / "config.yaml"
    config.write_text("ui:\n  title: Test\n", encoding="utf-8")
    monkeypatch.setenv("SCAN_SERVICE_CONFIG", str(config))
    assert Settings.from_environment().timezone == "Asia/Shanghai"


@pytest.mark.parametrize("zone", ["Invalid/Zone", "", "/etc/localtime"])
def test_invalid_timezone_fails_when_settings_are_loaded(tmp_path, monkeypatch, settings, zone):
    config = tmp_path / "config.yaml"
    config.write_text(f'ui:\n  timezone: "{zone}"\n', encoding="utf-8")
    monkeypatch.setenv("SCAN_SERVICE_CONFIG", str(config))
    with pytest.raises(ValueError, match="ui.timezone"):
        Settings.from_environment()
    with pytest.raises(ValueError, match="ui.timezone"):
        replace(settings, timezone=zone)
