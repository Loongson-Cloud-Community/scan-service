import json

from scanservice.modules.srpm.parsers.csmock import (
    classify_artifact,
    parse_nvr_from_path,
    parse_sarif,
    parse_scan_ini,
    parse_summary,
    summarize_findings,
)


def test_parse_scan_ini():
    metadata = parse_scan_ini(
        """
[scan]
tool = csmock
tool-version = csmock-3.8.7-2.ocs23
enabled-plugins = clang, cppcheck gcc shellcheck
mock-config = opencloudos-23-loongarch64
tool-args = --mock-config opencloudos-23-loongarch64
project-name = curl-8.4.0-9.ocs23
"""
    )
    assert metadata["scanner"] == "csmock"
    assert metadata["scanner_version"] == "csmock-3.8.7-2.ocs23"
    assert metadata["mock_config"] == "opencloudos-23-loongarch64"
    assert metadata["enabled_plugins"] == ["clang", "cppcheck", "gcc", "shellcheck"]
    assert metadata["tool_args"] == "--mock-config opencloudos-23-loongarch64"


def test_parse_summary_supports_checker_and_issue():
    rows = parse_summary(
        """
CLANG_WARNING: deadcode.DeadStores 13
CPPCHECK nullPointer 2
"""
    )
    assert rows == [
        {
            "checker": "CLANG_WARNING",
            "issue_type": "deadcode.DeadStores",
            "count": 13,
        },
        {"checker": "CPPCHECK", "issue_type": "nullPointer", "count": 2},
    ]


def test_parse_summary_supports_csmock_leading_count_format():
    rows = parse_summary(
        """
      1 CLANG_WARNING                                    warning[core.NullDereference]
      3 CLANG_WARNING                                    warning[deadcode.DeadStores]
     11 COMPILER_WARNING                                 warning[-Wformat=]
    """
    )
    assert rows == [
        {
            "checker": "CLANG_WARNING",
            "issue_type": "warning[core.NullDereference]",
            "count": 1,
        },
        {
            "checker": "CLANG_WARNING",
            "issue_type": "warning[deadcode.DeadStores]",
            "count": 3,
        },
        {
            "checker": "COMPILER_WARNING",
            "issue_type": "warning[-Wformat=]",
            "count": 11,
        },
    ]


def test_parse_sarif():
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "csdiff", "version": "3.5.4"}},
                "results": [
                    {
                        "ruleId": "core.NullDereference",
                        "level": "warning",
                        "message": {"text": "possible null dereference"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/main.c"},
                                    "region": {"startLine": 12, "startColumn": 4},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    parsed = parse_sarif(json.dumps(document))
    assert parsed["scanner"] == "csdiff"
    assert parsed["scanner_version"] == "3.5.4"
    assert len(parsed["findings"]) == 1
    assert parsed["findings"][0]["file_path"] == "src/main.c"
    assert parsed["findings"][0]["line"] == 12


def test_summarize_findings_falls_back_to_checker_and_rule():
    rows = summarize_findings(
        [
            {"checker": "csdiff", "rule_id": "deadcode.DeadStores"},
            {"checker": "csdiff", "rule_id": "deadcode.DeadStores"},
            {"checker": "csdiff", "rule_id": "core.NullDereference"},
        ]
    )
    assert rows == [
        {"checker": "csdiff", "issue_type": "deadcode.DeadStores", "count": 2},
        {"checker": "csdiff", "issue_type": "core.NullDereference", "count": 1},
    ]


def test_artifact_helpers():
    assert parse_nvr_from_path("curl-8.4.0-9.ocs23.tar.xz") == {
        "version": "8.4.0",
        "release": "9.ocs23",
        "nvr": "curl-8.4.0-9.ocs23",
    }
    assert classify_artifact("NVR/scan-results.html") == "REPORT_HTML"
    assert classify_artifact("NVR/scan-results-summary.txt") == "SUMMARY"
    assert classify_artifact("NVR/scan.log") == "LOG"
