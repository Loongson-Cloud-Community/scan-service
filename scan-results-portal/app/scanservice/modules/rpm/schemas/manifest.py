from typing import Literal

from pydantic import BaseModel, StrictStr, conint, constr

from ....scan_protocol import ExitCode, PackageFilename, ScanLocation, SchemaVersion, Sha256


class RpmMetadata(BaseModel):
    filename: PackageFilename
    sha256: Sha256
    name: constr(strict=True, max_length=200) | None = None
    epoch: constr(strict=True, max_length=50) | None = None
    version: constr(strict=True, max_length=200) | None = None
    release: constr(strict=True, max_length=200) | None = None
    architecture: constr(strict=True, max_length=100) | None = None
    source_rpm: PackageFilename | None = None
    size_bytes: conint(strict=True, ge=0, le=2**63 - 1) | None = None


class RpmScannerMetadata(BaseModel):
    name: Literal["cve-bin-tool"]
    version: constr(strict=True, max_length=100) | None = None
    exit_code: ExitCode
    args: list[StrictStr] | None = None


class RpmManifest(ScanLocation):
    schema_version: SchemaVersion
    scan_type: Literal["rpm"]
    scan_key: Sha256 | None = None
    rpm: RpmMetadata
    scanner: RpmScannerMetadata
