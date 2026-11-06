import json

from scanservice.modules.rpm.parsers.cve_bin_tool import (
    parse_manifest,
    parse_results,
    summarize,
)


def test_parse_rpm_manifest():
    manifest = parse_manifest(
        json.dumps(
            {
                "schema_version": 1,
                "scan_type": "rpm",
                "rpm": {
                    "filename": "docker-24.0.9-8.lns23.loongarch64.rpm",
                    "sha256": "a" * 64,
                },
                "scanner": {"name": "cve-bin-tool", "version": "3.4.1", "exit_code": 0},
            }
        ).encode()
    )
    assert manifest["rpm"]["filename"].startswith("docker-")


def test_parse_and_summarize_cve_bin_tool_results():
    rows = parse_results(
        json.dumps(
            [
                {
                    "vendor": "golang",
                    "product": "go",
                    "version": "1.24.13",
                    "cve_number": "CVE-2026-1",
                    "severity": "high",
                },
                {
                    "vendor": "mobyproject",
                    "product": "moby",
                    "version": "24.0.9",
                    "cve_number": "CVE-2026-2",
                    "severity": "CRITICAL",
                },
            ]
        ).encode()
    )
    summary = summarize(rows)
    assert summary["total"] == 2
    assert summary["high"] == 1
    assert summary["critical"] == 1
    assert len(summary["components"]) == 2
