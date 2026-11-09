"""Validate RPM scan outputs before publishing the Portal's accepted filenames."""

import json
import os
from pathlib import Path
import re
import sys


REPORT_FORMATS = ("json", "csv", "html")
ANSI_CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
# Rich can put the source location between the words and wrap the message.
# This is the confirmed cve-bin-tool extraction failure, not a general warning rule.
EXTRACTION_FAILURE = re.compile(
    r"\bWARNING\s+cve_bin_tool\.VersionScanner\s+-\s+"
    r"Failure\s+(?:extractor\.py:\d+\s+)?extracting\b"
)


class InvalidScan(ValueError):
    def __init__(self, reason, message):
        super().__init__(message)
        self.reason = reason


def validate_results(output_dir, scanner_exit, log_exit):
    if scanner_exit not in (0, 1):
        raise InvalidScan("SCANNER_FAILED", f"cve-bin-tool failed with exit code {scanner_exit}")
    if log_exit != 0:
        raise InvalidScan("LOG_WRITE_FAILED", f"Unable to capture scan.log: tee exit code {log_exit}")
    log = ANSI_CSI.sub("", (output_dir / "scan.log").read_text(encoding="utf-8", errors="replace"))
    if EXTRACTION_FAILURE.search(log):
        raise InvalidScan("EXTRACTION_FAILED", "cve-bin-tool reported Failure extracting; scan is incomplete")
    for extension in REPORT_FORMATS:
        path = output_dir / f"unvalidated-results.{extension}"
        if not path.is_file() or path.stat().st_size == 0:
            raise InvalidScan("INVALID_REPORT", f"Expected report is missing or empty: {path.name}")
    try:
        document = json.loads((output_dir / "unvalidated-results.json").read_text(encoding="utf-8"))
    except ValueError as error:
        raise InvalidScan("INVALID_REPORT", f"Invalid cve-bin-tool JSON report: {error}") from error
    if not isinstance(document, list):
        raise InvalidScan("INVALID_REPORT", "cve-bin-tool JSON report must contain a list")


def scan_manifest():
    return {
        "schema_version": 1,
        "scan_type": "rpm",
        "rpm": {
            "filename": os.environ["RPM_SCAN_FILENAME"],
            "name": os.environ["RPM_SCAN_NAME"],
            "epoch": os.environ["RPM_SCAN_EPOCH"],
            "version": os.environ["RPM_SCAN_VERSION"],
            "release": os.environ["RPM_SCAN_RELEASE"],
            "architecture": os.environ["RPM_SCAN_ARCH"],
            "source_rpm": os.environ["RPM_SCAN_SOURCE_RPM"],
            "sha256": os.environ["RPM_SCAN_SHA256"],
            "size_bytes": int(os.environ["RPM_SCAN_SIZE"]),
        },
        "scanner": {
            "name": "cve-bin-tool",
            "version": os.environ["RPM_SCAN_SCANNER_VERSION"],
            "exit_code": int(os.environ["RPM_SCAN_EXIT_CODE"]),
            "args": [
                "--update", os.environ["RPM_SCAN_UPDATE_MODE"],
                "--detailed", "--format", "csv,json,html",
            ],
        },
        "started_at": os.environ["RPM_SCAN_STARTED_AT"],
        "finished_at": os.environ["RPM_SCAN_FINISHED_AT"],
    }


def main():
    output_dir = Path(os.environ["RPM_SCAN_OUTPUT_DIR"])
    manifest = scan_manifest()
    scanner_exit = manifest["scanner"]["exit_code"]
    try:
        validate_results(output_dir, scanner_exit, int(os.environ["RPM_SCAN_LOG_EXIT_CODE"]))
        for extension in REPORT_FORMATS:
            (output_dir / f"unvalidated-results.{extension}").replace(output_dir / f"scan-results.{extension}")
        # Publish the manifest last; interrupted writes must not expose a partial
        # or successful-looking manifest alongside the reports.
        pending_manifest = output_dir / "scan-manifest.json.tmp"
        pending_manifest.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        pending_manifest.replace(output_dir / "scan-manifest.json")
        return 0
    except (InvalidScan, OSError) as error:
        manifest["validation"] = {
            "status": "FAILED",
            "reason": error.reason if isinstance(error, InvalidScan) else "OUTPUT_IO_FAILED",
            "message": str(error),
        }
        print(f"RPM scan validation failed: {error}", file=sys.stderr)
        try:
            (output_dir / "scan-failure.json").write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
            )
        except OSError as write_error:
            print(f"Unable to save scan-failure.json: {write_error}", file=sys.stderr)
        # Preserve real scanner errors, but do not invent a different scanner
        # exit code when only the agent's validation failed.
        return scanner_exit if scanner_exit not in (0, 1) else 3


if __name__ == "__main__":
    sys.exit(main())
