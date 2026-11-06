"""Shared input constraints and identity checks for the scan protocol."""

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, conint, constr, validator


BuildNumber = conint(strict=True, gt=0, le=2**31 - 1)
ExitCode = conint(strict=True, ge=-(2**31), le=2**31 - 1)
SchemaVersion = conint(strict=True, ge=1, le=1)
Sha256 = constr(strict=True, min_length=64, max_length=64, regex=r"^[0-9a-f]{64}\Z")
JobName = constr(strict=True, min_length=1, max_length=500)
PackageFilename = constr(
    strict=True, min_length=1, max_length=500, regex=r"^[^/\\\x00-\x1f\x7f]+\.rpm\Z",
)
SrpmFilename = constr(
    strict=True, min_length=1, max_length=500, regex=r"^[^/\\\x00-\x1f\x7f]+\.(?:src|nosrc)\.rpm\Z",
)


class ScanLocation(BaseModel):
    # Manifests may repeat the Jenkins location; events must provide it.
    jenkins_job_full_name: JobName | None = None
    jenkins_build_number: BuildNumber | None = None

    @validator("jenkins_job_full_name")
    def valid_job_name(cls, value):
        if value is not None and (
            not value.strip()
            or any(part in {"", ".", ".."} for part in value.split("/"))
            or any(ord(char) < 32 or ord(char) == 127 for char in value)
            or "\\" in value
        ):
            raise ValueError("invalid Jenkins job path")
        return value


class ScanEventRequest(ScanLocation):
    event: Literal["started", "completed", "failed"]
    jenkins_build_number: BuildNumber
    jenkins_job_full_name: JobName
    created_at: datetime | None = None
    finished_at: datetime | None = None

    @validator("created_at", "finished_at", pre=True)
    def timestamp_type(cls, value):
        if value is not None and not isinstance(value, (str, datetime)):
            raise ValueError("scan timestamps must be ISO-8601 strings")
        return value

    @validator("created_at", "finished_at")
    def timezone_required(cls, value):
        if value is not None and value.utcoffset() is None:
            raise ValueError("scan timestamps must include a timezone")
        return value


class ScanIdentityConflict(ValueError):
    """The event or artifact belongs to a different package or task."""


def require_matching_identity(expected: Mapping[str, Any], incoming: Mapping[str, Any]) -> None:
    """Reject conflicting evidence before changing any task fields."""
    for field, value in expected.items():
        candidate = incoming.get(field)
        if value is not None and candidate is not None and value != candidate:
            raise ScanIdentityConflict(f"scan identity mismatch: {field}")
