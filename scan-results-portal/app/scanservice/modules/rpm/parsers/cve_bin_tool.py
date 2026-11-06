from __future__ import annotations

from collections import Counter
import hashlib
import json
from typing import Any

from ..schemas.manifest import RpmManifest


REQUIRED_RESULT_FIELDS = {
    "vendor",
    "product",
    "version",
    "cve_number",
    "severity",
}


def parse_manifest(content: bytes) -> dict[str, Any]:
    document = json.loads(content.decode("utf-8"))
    if not isinstance(document, dict):
        raise ValueError("invalid RPM scan manifest")
    RpmManifest.parse_obj(document)
    return document


def parse_results(content: bytes) -> list[dict[str, Any]]:
    document = json.loads(content.decode("utf-8"))
    if not isinstance(document, list):
        raise ValueError("cve-bin-tool result must be a list")
    rows = []
    for raw in document:
        if not isinstance(raw, dict) or not REQUIRED_RESULT_FIELDS.issubset(raw):
            raise ValueError("cve-bin-tool result contains an invalid row")
        row = dict(raw)
        row["severity"] = str(row.get("severity") or "UNKNOWN").upper()
        rows.append(row)
    return rows


def result_fingerprint(row: dict[str, Any]) -> str:
    values = (
        row.get("vendor"),
        row.get("product"),
        row.get("version"),
        row.get("cve_number"),
        row.get("paths"),
    )
    return hashlib.sha256("\0".join(str(value or "") for value in values).encode()).hexdigest()


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    components = Counter(
        (str(row["vendor"]), str(row["product"]), str(row["version"]))
        for row in rows
    )
    severities = Counter(str(row["severity"]).upper() for row in rows)
    return {
        "total": len({str(row["cve_number"]) for row in rows}),
        "components": [
            {
                "vendor": vendor,
                "product": product,
                "version": version,
                "vulnerability_count": count,
            }
            for (vendor, product, version), count in sorted(components.items())
        ],
        "critical": severities["CRITICAL"],
        "high": severities["HIGH"],
        "medium": severities["MEDIUM"],
        "low": severities["LOW"],
        "unknown": sum(
            count
            for severity, count in severities.items()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        ),
    }
