"""Shared fixtures and helpers for the portal test suite."""

from __future__ import annotations

import io
import json
import os
import tarfile
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from sqlalchemy.schema import CreateSchema, DropSchema

from scanservice.config import Settings
from scanservice.db import Base

# Importing the model modules registers every table on Base.metadata so the
# in-memory database created below has the full schema.
from scanservice.modules.rpm import models as _rpm_models  # noqa: F401
from scanservice.modules.srpm import models as _srpm_models  # noqa: F401


RPM_SCAN_KEY = "a" * 64
RPM_BUILD_NUMBER = 7
RPM_ARTIFACT_PREFIX = f"rpm-scan-artifacts/{RPM_BUILD_NUMBER}/{RPM_SCAN_KEY}"
SRPM_BUILD_NUMBER = 6

SRPM_SCAN_FILES = (
    "scan.ini",
    "scan-results-summary.txt",
    "scan-results.js",
    "scan-results.err",
    "scan-results.html",
    "scan.log",
)

SRPM_SCAN_INI = """
[scan]
tool = csmock
tool-version = csmock-3.8.7-2.ocs23
mock-config = opencloudos-23-loongarch64
project-name = curl-8.4.0-9.ocs23
exit-code = 0
"""

SRPM_SUMMARY = """
CLANG_WARNING: deadcode.DeadStores 13
"""


@pytest.fixture
def pg_engine():
    """Give each PostgreSQL test its own schema, never the service database."""
    url = os.environ.get("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL is required for PostgreSQL tests")
    admin = create_engine(url)
    if admin.dialect.name != "postgresql":
        admin.dispose()
        pytest.fail("PostgreSQL tests require PostgreSQL")
    schema = f"scan_test_{uuid4().hex}"
    with admin.begin() as connection:
        connection.execute(CreateSchema(schema))
    engine = admin.execution_options(schema_translate_map={None: schema})
    try:
        Base.metadata.create_all(engine)
        yield engine
    finally:
        with admin.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True))
        admin.dispose()


@pytest.fixture
def session():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    with factory() as db:
        yield db


@pytest.fixture(params=["sqlite", "postgresql"])
def query_engine(request):
    if request.param == "postgresql":
        yield request.getfixturevalue("pg_engine")
    else:
        engine = create_engine("sqlite://", poolclass=StaticPool,
                               connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        try:
            yield engine
        finally:
            engine.dispose()


@pytest.fixture
def settings():
    return Settings(
        database_url="sqlite://",
        jenkins_base_url="http://jenkins",
        jenkins_user="user",
        jenkins_token="token",
        ingest_token="ingest",
        operator_token="operator",
        operator_sync_rate_limit=6,
        recent_build_limit=20,
        request_timeout_seconds=5,
        title="Test Portal",
        page_size=50,
    )


class FakeJenkinsClient:
    """Jenkins client stub serving a single build and its artifact contents."""

    def __init__(
        self,
        *,
        building: bool = False,
        result: str = "SUCCESS",
        artifacts: list[dict] | None = None,
        contents: dict[str, bytes] | None = None,
        causes: tuple[dict, ...] = (),
    ) -> None:
        self.building = building
        self.result = result
        self.artifacts = list(artifacts or [])
        self.contents = dict(contents or {})
        self.causes = list(causes)
        self.requested_builds: list[tuple[str, int]] = []
        self.requested_artifacts: list[str] = []
        self.closed = False

    def get_build(self, job_name: str, number: int) -> dict:
        self.requested_builds.append((job_name, int(number)))
        return {
            "number": int(number),
            "url": f"http://jenkins/job/{job_name}/{number}/",
            "building": self.building,
            "result": self.result,
            "artifacts": self.artifacts,
            "actions": [{"causes": self.causes}] if self.causes else [],
        }

    def get_artifact(
        self,
        job_name: str,
        number: int,
        relative_path: str,
        *,
        max_bytes: int | None = None,
    ) -> bytes:
        self.requested_artifacts.append(relative_path)
        try:
            content = self.contents[relative_path]
        except KeyError as exc:
            raise KeyError(f"unexpected artifact request: {relative_path}") from exc
        if max_bytes is not None and len(content) > max_bytes:
            raise ValueError("artifact exceeds configured limit")
        return content

    def iter_artifact(
        self,
        job_name: str,
        number: int,
        relative_path: str,
        *,
        max_bytes: int,
        chunk_size: int = 64 * 1024,
    ):
        content = self.get_artifact(
            job_name,
            number,
            relative_path,
            max_bytes=max_bytes,
        )
        for offset in range(0, len(content), chunk_size):
            yield content[offset : offset + chunk_size]

    def _url(self, path: str) -> str:
        return f"http://jenkins/{path.lstrip('/')}"

    @staticmethod
    def _job_path(job_name: str) -> str:
        parts = [part for part in job_name.strip("/").split("/") if part]
        return "/".join(f"job/{part}" for part in parts)

    def close(self) -> None:
        self.closed = True


def rpm_manifest(exit_code: int = 0, sha256: str = RPM_SCAN_KEY) -> dict:
    return {
        "schema_version": 1,
        "scan_type": "rpm",
        "rpm": {
            "filename": "docker-24.0.9-8.lns23.loongarch64.rpm",
            "name": "docker",
            "epoch": "8",
            "version": "24.0.9",
            "release": "8.lns23",
            "architecture": "loongarch64",
            "source_rpm": "docker-24.0.9-8.lns23.src.rpm",
            "sha256": sha256,
            "size_bytes": 16764070,
        },
        "scanner": {
            "name": "cve-bin-tool",
            "version": "3.4.1",
            "exit_code": exit_code,
            "args": ["--update", "never", "--detailed", "--format", "csv,json,html"],
        },
        "started_at": "2026-10-01T10:00:00+08:00",
        "finished_at": "2026-10-01T10:05:00+08:00",
    }


def rpm_results() -> list[dict]:
    return [
        {
            "vendor": "golang",
            "product": "go",
            "version": "1.24.13",
            "cve_number": "CVE-2026-0001",
            "severity": "high",
            "score": "7.5",
            "paths": "/usr/bin/dockerd",
        },
        {
            "vendor": "golang",
            "product": "go",
            "version": "1.24.13",
            "cve_number": "CVE-2026-0002",
            "severity": "low",
            "score": "",
            "paths": "/usr/bin/dockerd",
        },
    ]


def rpm_scan_artifacts(
    *,
    prefix: str = RPM_ARTIFACT_PREFIX,
    exit_code: int = 0,
    sha256: str = RPM_SCAN_KEY,
    names: tuple[str, ...] = (
        "scan-manifest.json",
        "scan-results.json",
        "scan-results.csv",
        "scan-results.html",
        "scan.log",
    ),
) -> tuple[list[dict], dict[str, bytes]]:
    """Return (build artifact rows, artifact contents) for one RPM scan."""
    contents: dict[str, bytes] = {}
    for name in names:
        if name == "scan-manifest.json":
            payload = json.dumps(rpm_manifest(exit_code=exit_code, sha256=sha256))
        elif name == "scan-results.json":
            payload = json.dumps(rpm_results())
        else:
            payload = f"{name}\n"
        contents[f"{prefix}/{name}"] = payload.encode()
    rows = [
        {
            "fileName": path.rsplit("/", 1)[-1],
            "relativePath": path,
            "size": len(payload),
            "url": None,
        }
        for path, payload in contents.items()
    ]
    return rows, contents


def srpm_archive_bytes(members: dict[str, str] | None = None) -> bytes:
    """Build a csmock-like .tar.xz holding the six expected result files."""
    if members is None:
        members = {
            "scan.ini": SRPM_SCAN_INI,
            "scan-results-summary.txt": SRPM_SUMMARY,
            "scan-results.js": "/* js */\n",
            "scan-results.err": "err\n",
            "scan-results.html": "<html></html>\n",
            "scan.log": "log\n",
        }
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
        for name, text in members.items():
            data = text.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def srpm_scan_artifacts(
    *,
    build_number: int = SRPM_BUILD_NUMBER,
    nvr: str = "curl-8.4.0-9.ocs23",
    members: dict[str, str] | None = None,
) -> tuple[list[dict], dict[str, bytes]]:
    """Return (build artifact rows, artifact contents) for one SRPM scan."""
    archive_name = f"{nvr}.tar.xz"
    relative_path = f"srpm-scan-artifacts/{build_number}/{archive_name}"
    content = srpm_archive_bytes(members=members)
    rows = [
        {
            "fileName": archive_name,
            "relativePath": relative_path,
            "size": len(content),
            "url": None,
        }
    ]
    return rows, {relative_path: content}


async def response_body(response) -> bytes:
    body = getattr(response, "body", None)
    if body is not None:
        return body
    chunks = []
    async for chunk in response.body_iterator:
        chunks.append(chunk.encode() if isinstance(chunk, str) else chunk)
    return b"".join(chunks)
