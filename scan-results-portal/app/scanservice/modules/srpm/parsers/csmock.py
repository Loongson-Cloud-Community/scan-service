from __future__ import annotations

import configparser
import hashlib
import json
import re
from typing import Any


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, dict):
        value = value.get("text") or value.get("markdown") or value
    return str(value)


def parse_scan_ini(content: str) -> dict[str, Any]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read_string(content)

    section: dict[str, str] = {}
    if parser.has_section("scan"):
        section = dict(parser.items("scan"))

    plugins = section.get("enabled-plugins", "")
    return {
        "scanner": section.get("tool"),
        "scanner_version": section.get("tool-version"),
        "method": section.get("method"),
        "args": section.get("args"),
        "csmock_args": section.get("csmock_args") or section.get("csmock-args"),
        "tool_args": section.get("tool-args"),
        "mock_config": section.get("mock-config"),
        "enabled_plugins": [item for item in re.split(r"[,\s]+", plugins) if item],
        "project_name": section.get("project-name"),
        "host": section.get("host"),
        "time_created": section.get("time-created"),
        "store_results_to": section.get("store-results-to"),
        "raw": section,
    }


def parse_summary(content: str) -> list[dict[str, Any]]:
    """Accept empty clean results, but never silently discard malformed rows."""
    summaries: list[dict[str, Any]] = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        leading_count_match = re.match(r"^(\d+)\s+(\S+)\s+(.+?)\s*$", line)
        if leading_count_match:
            summaries.append(
                {
                    "checker": leading_count_match.group(2),
                    "issue_type": leading_count_match.group(3),
                    "count": int(leading_count_match.group(1)),
                }
            )
            continue

        count_match = re.search(r"(?<![-\w.])(\d+)\s*$", line)
        if not count_match:
            raise ValueError("scan-results-summary.txt contains an unrecognized row")
        count = int(count_match.group(1))
        body = line[: count_match.start()].strip(" \t:=")
        if not body:
            raise ValueError("scan-results-summary.txt contains a count without a checker")

        checker = "csmock"
        issue_type = body
        if ":" in body:
            candidate, remainder = body.split(":", 1)
            if remainder.strip():
                checker = candidate.strip()
                issue_type = remainder.strip()
        else:
            parts = body.split(None, 1)
            if len(parts) == 2 and (
                parts[0].isupper()
                or parts[0].lower() in {"clang", "cppcheck", "gcc", "shellcheck"}
                or "warning" in parts[0].lower()
            ):
                checker, issue_type = parts[0], parts[1]

        summaries.append(
            {"checker": checker, "issue_type": issue_type, "count": count}
        )
    return summaries


def _fingerprint(
    result: dict[str, Any], file_path: str | None, line: int | None
) -> str:
    fingerprints = result.get("fingerprints") or {}
    for value in fingerprints.values():
        if value:
            return str(value)
    identity = {
        "rule_id": result.get("ruleId"),
        "message": _text(result.get("message")),
        "file_path": file_path,
        "line": line,
    }
    return hashlib.sha1(
        json.dumps(identity, sort_keys=True, ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def parse_sarif(content: str) -> dict[str, Any]:
    document = json.loads(content)
    findings: list[dict[str, Any]] = []
    scanner = None
    scanner_version = None

    for run in document.get("runs", []):
        driver = ((run.get("tool") or {}).get("driver") or {})
        scanner = scanner or driver.get("name")
        scanner_version = scanner_version or driver.get("version")
        for result in run.get("results", []):
            locations = result.get("locations") or [{}]
            location = locations[0] or {}
            physical = location.get("physicalLocation") or {}
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}
            file_path = artifact.get("uri")
            line = region.get("startLine")
            column = region.get("startColumn")
            findings.append(
                {
                    "fingerprint": _fingerprint(result, file_path, line),
                    "checker": driver.get("name"),
                    "rule_id": result.get("ruleId"),
                    "severity": result.get("level"),
                    "message": _text(result.get("message")),
                    "file_path": file_path,
                    "line": line,
                    "column": column,
                    "code_context": _text(region.get("snippet")),
                    "raw": result,
                }
            )

    return {
        "scanner": scanner,
        "scanner_version": scanner_version,
        "findings": findings,
    }


def summarize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Build a stable summary when Jenkins archives SARIF without text summary."""
    counts: dict[tuple[str, str], int] = {}
    for finding in findings:
        checker = str(finding.get("checker") or "unknown")
        issue_type = str(finding.get("rule_id") or "unspecified")
        key = (checker, issue_type)
        counts[key] = counts.get(key, 0) + 1
    return [
        {"checker": checker, "issue_type": issue_type, "count": count}
        for (checker, issue_type), count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0][0], item[0][1])
        )
    ]


def parse_nvr_from_path(path: str) -> dict[str, str] | None:
    name = path.rsplit("/", 1)[-1]
    for suffix in (".tar.xz", ".tar.gz", ".tar.bz2", ".zip"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    else:
        return None

    parts = name.rsplit("-", 2)
    if len(parts) != 3 or not all(parts):
        return None
    _, version, release = parts
    return {"version": version, "release": release, "nvr": name}


def classify_artifact(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    if name.endswith(".html"):
        return "REPORT_HTML"
    if name.endswith(".json") or name.endswith(".js") or name.endswith(".sarif"):
        return "REPORT_JSON"
    if name == "scan.ini" or name == "scan-manifest.json":
        return "METADATA"
    if "summary" in name:
        return "SUMMARY"
    if name.endswith(".log") or name.endswith(".err"):
        return "LOG"
    if name.endswith((".tar.xz", ".tar.gz", ".zip")):
        return "ARCHIVE"
    return "OTHER"
