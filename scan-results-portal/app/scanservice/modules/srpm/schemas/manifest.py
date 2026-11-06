from typing import Literal

from pydantic import BaseModel, StrictStr, constr

from ....scan_protocol import ExitCode, ScanLocation, SchemaVersion, Sha256, SrpmFilename


class SrpmScannerMetadata(BaseModel):
    name: Literal["csmock"]
    version: constr(strict=True, max_length=100) | None = None


class SrpmManifest(ScanLocation):
    # The existing optional flat metadata has no version field. If supplied,
    # only the currently supported version is accepted.
    schema_version: SchemaVersion = 1
    scan_type: Literal["srpm"] = "srpm"
    package_name: constr(strict=True, max_length=200) | None = None
    version: constr(strict=True, max_length=200) | None = None
    release: constr(strict=True, max_length=200) | None = None
    nvr: constr(strict=True, max_length=500) | None = None
    srpm_name: SrpmFilename | None = None
    architecture: constr(strict=True, max_length=100) | None = None
    source_revision: constr(strict=True, max_length=500) | None = None
    source_url: StrictStr | None = None
    source_sha256: Sha256 | None = None
    mock_config: constr(strict=True, max_length=300) | None = None
    gate_result: constr(strict=True, max_length=30) | None = None
    scanner: Literal["csmock"] | SrpmScannerMetadata | None = None
    scanner_version: constr(strict=True, max_length=100) | None = None
    csmock_exit_code: ExitCode | None = None
    plugins: list[StrictStr] | None = None
    enabled_plugins: list[StrictStr] | None = None
