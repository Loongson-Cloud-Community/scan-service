from __future__ import annotations

from ....scan_protocol import ExitCode, ScanEventRequest, SrpmFilename


class SrpmEventRequest(ScanEventRequest):
    srpm_name: SrpmFilename | None = None
    csmock_exit_code: ExitCode | None = None
