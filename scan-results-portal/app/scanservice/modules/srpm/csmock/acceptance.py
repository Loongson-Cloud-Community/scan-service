from __future__ import annotations

from typing import Any


def validated_exit_code(
    metadata: dict[str, Any], reported: int | None, *, srpm_name: str | None = None,
) -> int:
    """Require csmock metadata and a known outcome; failure evidence wins."""
    if metadata.get("scanner") != "csmock":
        raise ValueError("scan.ini must identify csmock in the [scan] section")
    if srpm_name is not None:
        nvr = srpm_name.rsplit(".", 2)[0]
        if metadata.get("project_name") != nvr:
            raise ValueError("scan.ini project-name does not match the registered SRPM")
    raw_code = metadata["raw"].get("exit-code")
    ini_code = None
    if raw_code is not None:
        try:
            ini_code = int(raw_code)
            if not -(2**31) <= ini_code <= 2**31 - 1:
                raise ValueError("exit code is outside the supported integer range")
        except ValueError as exc:
            raise ValueError("scan.ini has an invalid exit-code") from exc
    codes = [code for code in (reported, ini_code) if code is not None]
    if not codes:
        raise ValueError("csmock exit code is unavailable from both scan.ini and callback")
    return next((code for code in codes if code != 0), 0)
