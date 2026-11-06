from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class ArtifactLimits:
    max_parse_bytes: int = 16 * 1024 * 1024
    max_download_bytes: int = 1024 * 1024 * 1024
    max_archive_bytes: int = 128 * 1024 * 1024
    max_archive_members: int = 4096
    max_archive_member_bytes: int = 64 * 1024 * 1024
    max_archive_uncompressed_bytes: int = 512 * 1024 * 1024
    max_archive_compression_ratio: float = 200.0

    def __post_init__(self) -> None:
        values = (
            self.max_parse_bytes,
            self.max_download_bytes,
            self.max_archive_bytes,
            self.max_archive_members,
            self.max_archive_member_bytes,
            self.max_archive_uncompressed_bytes,
            self.max_archive_compression_ratio,
        )
        if any(value <= 0 for value in values):
            raise ValueError("artifact limits must all be positive")


def _read_yaml(path: str) -> dict[str, Any]:
    config_path = Path(path)
    if not config_path.is_file():
        return {}
    with config_path.open("r", encoding="utf-8") as stream:
        loaded = yaml.safe_load(stream)
    return loaded if isinstance(loaded, dict) else {}


def _env_or(mapping: dict[str, Any], key: str, env_name: str, default: Any) -> Any:
    value = os.getenv(env_name)
    if value not in {None, ""}:
        return value
    return mapping.get(key, default)


@dataclass(frozen=True)
class Settings:
    database_url: str
    jenkins_base_url: str
    jenkins_user: str
    jenkins_token: str
    ingest_token: str
    operator_token: str
    operator_sync_rate_limit: int
    recent_build_limit: int
    request_timeout_seconds: float
    title: str
    page_size: int
    artifact_limits: ArtifactLimits = field(default_factory=ArtifactLimits)

    @classmethod
    def from_environment(cls) -> "Settings":
        config = _read_yaml(os.getenv("SCAN_SERVICE_CONFIG", "/etc/scan-service/config.yaml"))
        jenkins = config.get("jenkins", {})
        sync = config.get("sync", {})
        ui = config.get("ui", {})
        artifacts = config.get("artifacts", {})

        artifact_limits = ArtifactLimits(
            max_parse_bytes=int(
                _env_or(artifacts, "max_parse_bytes", "MAX_PARSE_BYTES", 16 * 1024 * 1024)
            ),
            max_download_bytes=int(
                _env_or(
                    artifacts,
                    "max_download_bytes",
                    "MAX_ARTIFACT_DOWNLOAD_BYTES",
                    1024 * 1024 * 1024,
                )
            ),
            max_archive_bytes=int(
                _env_or(
                    artifacts,
                    "max_archive_bytes",
                    "MAX_ARCHIVE_BYTES",
                    128 * 1024 * 1024,
                )
            ),
            max_archive_members=int(
                _env_or(
                    artifacts,
                    "max_archive_members",
                    "MAX_ARCHIVE_MEMBERS",
                    4096,
                )
            ),
            max_archive_member_bytes=int(
                _env_or(
                    artifacts,
                    "max_archive_member_bytes",
                    "MAX_ARCHIVE_MEMBER_BYTES",
                    64 * 1024 * 1024,
                )
            ),
            max_archive_uncompressed_bytes=int(
                _env_or(
                    artifacts,
                    "max_archive_uncompressed_bytes",
                    "MAX_ARCHIVE_UNCOMPRESSED_BYTES",
                    512 * 1024 * 1024,
                )
            ),
            max_archive_compression_ratio=float(
                _env_or(
                    artifacts,
                    "max_archive_compression_ratio",
                    "MAX_ARCHIVE_COMPRESSION_RATIO",
                    200.0,
                )
            ),
        )

        return cls(
            database_url=os.getenv("DATABASE_URL", "sqlite:///./scanservice.db"),
            jenkins_base_url=str(_env_or(jenkins, "base_url", "JENKINS_BASE_URL", "")),
            jenkins_user=os.getenv("JENKINS_USER", ""),
            jenkins_token=os.getenv("JENKINS_TOKEN", ""),
            ingest_token=os.getenv("SCAN_SERVICE_INGEST_TOKEN", ""),
            operator_token=os.getenv("SCAN_SERVICE_OPERATOR_TOKEN", ""),
            operator_sync_rate_limit=int(
                os.getenv("OPERATOR_SYNC_RATE_LIMIT_PER_MINUTE", "6")
            ),
            recent_build_limit=int(
                _env_or(sync, "recent_build_limit", "RECENT_BUILD_LIMIT", 20)
            ),
            request_timeout_seconds=float(
                _env_or(sync, "request_timeout_seconds", "JENKINS_TIMEOUT", 15)
            ),
            title=str(_env_or(ui, "title", "SCAN_SERVICE_TITLE", "Scan Results Portal")),
            page_size=int(ui.get("page_size", 50)),
            artifact_limits=artifact_limits,
        )


@lru_cache
def get_settings() -> Settings:
    return Settings.from_environment()
