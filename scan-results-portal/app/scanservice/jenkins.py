from __future__ import annotations

from collections.abc import Iterator
from typing import Any
from urllib.parse import quote

import httpx


class JenkinsError(RuntimeError):
    pass


class JenkinsArtifactTooLarge(JenkinsError):
    pass


class JenkinsArtifactNotFound(JenkinsError):
    pass


class JenkinsClient:
    def __init__(
        self,
        base_url: str,
        user: str = "",
        token: str = "",
        timeout: float = 15,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(
            auth=(user, token) if user or token else None,
            timeout=timeout,
            follow_redirects=True,
        )

    def close(self) -> None:
        self.client.close()

    @staticmethod
    def _job_path(job_name: str) -> str:
        parts = [part for part in job_name.strip("/").split("/") if part]
        return "/".join(f"job/{quote(part, safe='')}" for part in parts)

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _get_json(self, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self.client.get(self._url(path), params=params)
        if response.status_code >= 400:
            raise JenkinsError(
                f"Jenkins returned HTTP {response.status_code} for {path}"
            )
        try:
            return response.json()
        except ValueError as exc:
            raise JenkinsError(f"Jenkins returned non-JSON data for {path}") from exc

    def get_build(self, job_name: str, number: int) -> dict[str, Any]:
        return self._get_json(
            f"{self._job_path(job_name)}/{number}/api/json",
            {
                "tree": (
                    "number,url,result,building,timestamp,duration,"
                    "displayName,artifacts[fileName,relativePath,size,url],"
                    "actions[causes[userId,userName,shortDescription]]"
                ),
            },
        )

    def _artifact_url(self, job_name: str, number: int, relative_path: str) -> str:
        path = "/".join(
            quote(part, safe="") for part in relative_path.strip("/").split("/")
        )
        return self._url(f"{self._job_path(job_name)}/{number}/artifact/{path}")

    @staticmethod
    def _check_content_length(response: httpx.Response, max_bytes: int) -> None:
        value = response.headers.get("content-length")
        if value is not None and int(value) > max_bytes:
            raise JenkinsArtifactTooLarge(
                f"artifact exceeds the configured {max_bytes}-byte limit"
            )

    def iter_artifact(
        self,
        job_name: str,
        number: int,
        relative_path: str,
        *,
        max_bytes: int,
        chunk_size: int = 64 * 1024,
    ) -> Iterator[bytes]:
        with self.client.stream(
            "GET", self._artifact_url(job_name, number, relative_path)
        ) as response:
            if response.status_code == 404:
                raise JenkinsArtifactNotFound("Jenkins artifact not found")
            if response.status_code >= 400:
                raise JenkinsError(
                    f"Jenkins returned HTTP {response.status_code} for artifact"
                )
            self._check_content_length(response, max_bytes)
            total = 0
            for chunk in response.iter_bytes(chunk_size=chunk_size):
                total += len(chunk)
                if total > max_bytes:
                    raise JenkinsArtifactTooLarge(
                        f"artifact exceeds the configured {max_bytes}-byte limit"
                    )
                yield chunk

    def get_artifact(
        self,
        job_name: str,
        number: int,
        relative_path: str,
        *,
        max_bytes: int,
    ) -> bytes:
        return b"".join(
            self.iter_artifact(
                job_name,
                number,
                relative_path,
                max_bytes=max_bytes,
            )
        )
