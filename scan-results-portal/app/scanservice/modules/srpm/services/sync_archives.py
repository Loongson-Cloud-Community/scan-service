"""Acquire and index a bounded set of archives for one SRPM task."""

from contextlib import ExitStack, closing
import tarfile
from typing import Any

from sqlalchemy.orm import Session

from ....config import ArtifactLimits
from ....jenkins import JenkinsArtifactTooLarge, JenkinsClient
from ..csmock.archive import CsmockArchive
from ..csmock.budget import ArchiveBudget, ArchiveBudgetExceeded
from ..models import SrpmScanTask
from .sync_artifacts import is_archive, upsert_archive_members


def _download_archive(
    client: JenkinsClient, task: SrpmScanTask, path: str, budget: ArchiveBudget,
) -> bytes:
    chunks = []
    try:
        with closing(client.iter_artifact(
            task.jenkins_job_full_name, task.jenkins_build_number, path,
            max_bytes=budget.remaining_download_bytes,
        )) as stream:
            for chunk in stream:
                budget.download(len(chunk))
                chunks.append(chunk)
    except JenkinsArtifactTooLarge as exc:
        # The client may reject a declared length or an overflow chunk before
        # yielding it. Never continue with an unaccounted failed download.
        raise ArchiveBudgetExceeded("SRPM sync archive download budget exhausted") from exc
    return b"".join(chunks)


def load_scan_archives(
    session: Session, client: JenkinsClient, task: SrpmScanTask,
    artifacts: list[dict[str, Any]], limits: ArtifactLimits, stack: ExitStack,
) -> list[tuple[str, CsmockArchive]]:
    budget = ArchiveBudget(limits)
    archives = []
    top_level_names = {
        str(row.get("fileName") or str(row.get("relativePath") or "").rsplit("/", 1)[-1])
        for row in artifacts
    }
    for artifact in artifacts:
        path = str(artifact.get("relativePath") or artifact.get("fileName") or "")
        if not path or not is_archive(path):
            continue
        budget.start_archive()
        size = artifact.get("size")
        if size is not None and int(size) > limits.max_archive_bytes:
            continue
        # An interrupted download may have buffered bytes that were not yielded.
        # Abort rather than retrying other archives with an uncertain balance.
        content = _download_archive(client, task, path, budget)
        try:
            reader = stack.enter_context(CsmockArchive(content, limits, budget=budget))
        except ArchiveBudgetExceeded:
            raise
        except (OSError, tarfile.TarError, ValueError):
            continue
        finally:
            del content
        archives.append((path, reader))
        upsert_archive_members(session, task, path, reader.members, top_level_names)
    return archives
