from pydantic import root_validator

from ....scan_protocol import ExitCode, PackageFilename, ScanEventRequest, Sha256


class RpmEventRequest(ScanEventRequest):
    scan_key: Sha256
    rpm_name: PackageFilename
    rpm_sha256: Sha256
    cbt_exit_code: ExitCode | None = None

    @root_validator(skip_on_failure=True)
    def scan_key_matches_rpm(cls, values):
        if values["scan_key"] != values["rpm_sha256"]:
            raise ValueError("scan_key must equal rpm_sha256")
        return values
