"""Result pages must have bounded SQL reads, stable ordering and task isolation."""

import asyncio
from collections import Counter
from dataclasses import replace
from html import unescape
import re
from types import SimpleNamespace

from fastapi import FastAPI
import httpx
import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session

from scanservice.db import get_db
from scanservice.modules.rpm.models import (
    RpmScanArtifact, RpmScanComponent, RpmScanTask, RpmScanVulnerability,
)
from scanservice.modules.rpm.web import routes as rpm_web
from scanservice.modules.srpm.api import routes as srpm_api
from scanservice.modules.srpm.models import SrpmScanFinding, SrpmScanTask


@pytest.fixture
def results(query_engine, settings, monkeypatch):
    with Session(query_engine) as db:
        rpm = RpmScanTask(
            scan_key="a" * 64, rpm_sha256="a" * 64, rpm_name="demo.rpm",
            jenkins_job_full_name="demo", jenkins_build_number=1,
            state="FINISHED", total_vulnerabilities=3, high_count=3,
        )
        srpm = SrpmScanTask(jenkins_job_full_name="demo", jenkins_build_number=1)
        other_rpm = RpmScanTask(
            scan_key="b" * 64, rpm_sha256="b" * 64, rpm_name="other.rpm",
            jenkins_job_full_name="other", jenkins_build_number=1, state="FINISHED",
        )
        other_srpm = SrpmScanTask(jenkins_job_full_name="other", jenkins_build_number=1)
        empty_rpm = RpmScanTask(
            scan_key="e" * 64, rpm_sha256="e" * 64, rpm_name="empty.rpm",
            jenkins_job_full_name="empty", jenkins_build_number=1, state="FAILED",
        )
        empty_srpm = SrpmScanTask(jenkins_job_full_name="empty", jenkins_build_number=1)
        db.add_all([rpm, srpm, other_rpm, other_srpm, empty_rpm, empty_srpm])
        db.flush()
        rpm_id, srpm_id = rpm.id, srpm.id
        empty_rpm_id, empty_srpm_id = empty_rpm.id, empty_srpm.id
        vulnerabilities, findings = [], []
        for i in reversed(range(213)):
            vulnerability = RpmScanVulnerability(
                task_id=rpm.id, fingerprint=f"v-{i}", cve_number=f"CVE-2026-{i % 3:04}",
                vendor="vendor", product="vulnerable-product", version=str(i),
                severity="HIGH", description=f"evidence-{i}", paths=f"/bin/demo-{i}",
                raw={"large": "x" * 5000},
            )
            finding = SrpmScanFinding(task_id=srpm.id, fingerprint=f"f-{i}",
                                      message=f"finding-{i}", raw={"index": i})
            db.add_all([
                vulnerability, finding,
                RpmScanComponent(task_id=rpm.id, vendor="vendor", product=f"component-{i:04}",
                                 version="1", vulnerability_count=3),
            ])
            vulnerabilities.append(vulnerability)
            findings.append(finding)
        db.add_all([
            RpmScanVulnerability(task_id=other_rpm.id, fingerprint="foreign", cve_number="FOREIGN",
                                 vendor="foreign", product="foreign", version="1", severity="HIGH", raw={}),
            RpmScanComponent(task_id=other_rpm.id, vendor="foreign", product="foreign",
                             version="1", vulnerability_count=1),
            SrpmScanFinding(task_id=other_srpm.id, fingerprint="foreign", message="FOREIGN"),
            RpmScanArtifact(task_id=rpm.id, name="scan.log", artifact_type="LOG", relative_path="scan.log"),
        ])
        db.flush()
        expected_vulnerabilities = [row.id for row in sorted(
            vulnerabilities, key=lambda row: (row.severity, row.cve_number, row.vendor, row.product, row.id),
        )]
        expected_findings = [row.id for row in sorted(findings, key=lambda row: row.id)]
        db.commit()

    def database():
        with Session(query_engine) as db:
            yield db

    monkeypatch.setattr(rpm_web, "get_settings", lambda: settings)
    app = FastAPI()
    app.include_router(rpm_web.router)
    app.include_router(srpm_api.router)
    app.dependency_overrides[get_db] = database
    statements, loaded = [], Counter()

    def capture(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement.lower())

    def load(session, row):
        loaded[type(row)] += 1

    event.listen(query_engine, "before_cursor_execute", capture)
    event.listen(Session, "loaded_as_persistent", load)
    try:
        yield SimpleNamespace(app=app, rpm_id=rpm_id, srpm_id=srpm_id, statements=statements,
                              loaded=loaded, vulnerabilities=expected_vulnerabilities,
                              findings=expected_findings, empty_rpm_id=empty_rpm_id,
                              empty_srpm_id=empty_srpm_id)
    finally:
        event.remove(query_engine, "before_cursor_execute", capture)
        event.remove(Session, "loaded_as_persistent", load)


def get(results, path):
    async def exchange():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=results.app),
                                     base_url="http://test") as client:
            return await client.get(path)
    results.statements.clear()
    results.loaded.clear()
    return asyncio.run(exchange())


def assert_bounded_selects(results, *tables):
    for table in tables:
        selects = [sql for sql in results.statements
                   if re.search(rf"\bfrom (?:\w+\.)?{table}\b", sql) and "count(" not in sql]
        assert len(selects) == 1, results.statements
        assert "limit" in selects[0], selects[0]
        assert "order by" in selects[0], selects[0]


@pytest.mark.parametrize("page,size,count", [(1, 50, 50), (2, 7, 7), (31, 7, 3), (1, 200, 200)])
def test_findings_api_pages_are_bounded_and_keep_finding_fields(results, page, size, count):
    response = get(results, f"/api/v1/srpm/tasks/{results.srpm_id}/findings?page={page}&page_size={size}")
    assert response.status_code == 200
    body = response.json()
    assert {key: value for key, value in body.items() if key != "items"} == {
        "page": page, "page_size": size, "total": 213,
    }
    assert len(body["items"]) == count
    assert [row["id"] for row in body["items"]] == results.findings[(page - 1) * size:page * size]
    assert set(body["items"][0]) == {
        "id", "fingerprint", "checker", "rule_id", "severity", "message", "file_path",
        "line", "column", "code_context", "raw",
    }
    assert body["items"][0]["raw"] == {"index": 213 - (page - 1) * size - 1}
    assert results.loaded[SrpmScanFinding] == count
    assert len(results.statements) == 3
    assert_bounded_selects(results, "srpm_scan_finding")
    assert not any("scan_artifact" in sql or "scan_summary" in sql for sql in results.statements)


@pytest.mark.parametrize("query", ["page=0", "page=-1", "page=x", "page_size=0", "page_size=201", "page_size=x"])
def test_invalid_findings_pagination_rejected_before_sql(results, query):
    response = get(results, f"/api/v1/srpm/tasks/{results.srpm_id}/findings?{query}")
    assert response.status_code == 422
    assert results.statements == []


def test_findings_default_limit_and_full_traversal(results):
    ids = []
    for page in range(1, 6):
        response = get(results, f"/api/v1/srpm/tasks/{results.srpm_id}/findings?page={page}")
        assert response.status_code == 200
        body = response.json()
        assert body["page_size"] == 50
        ids.extend(row["id"] for row in body["items"])
    assert ids == results.findings
    assert len(set(ids)) == 213


@pytest.mark.parametrize("page", [999, 10 ** 30])
def test_out_of_range_findings_page_is_empty_without_overflow(results, page):
    response = get(results, f"/api/v1/srpm/tasks/{results.srpm_id}/findings?page={page}")
    assert response.status_code == 200
    assert response.json() == {"page": page, "page_size": 50, "total": 213, "items": []}
    assert results.loaded[SrpmScanFinding] == 0


def test_missing_finding_task_is_still_404(results):
    response = get(results, "/api/v1/srpm/tasks/99999/findings?page=2")
    assert response.status_code == 404
    assert len(results.statements) == 1


def test_empty_findings_page_preserves_task_existence_and_zero_total(results):
    response = get(results, f"/api/v1/srpm/tasks/{results.empty_srpm_id}/findings")
    assert response.status_code == 200
    assert response.json() == {"page": 1, "page_size": 50, "total": 0, "items": []}
    assert results.loaded[SrpmScanFinding] == 0
    assert len(results.statements) == 2


@pytest.mark.parametrize("component_page,vulnerability_page", [(1, 1), (2, 3), (5, 5)])
def test_rpm_results_have_independent_bounded_pages(results, component_page, vulnerability_page):
    response = get(results, f"/rpm/{results.rpm_id}?component_page={component_page}&vulnerability_page={vulnerability_page}")
    assert response.status_code == 200
    html = response.text
    start = (vulnerability_page - 1) * 50
    ids = [int(value) for value in re.findall(r'id="evidence-(\d+)"', html)]
    assert ids == results.vulnerabilities[start:start + 50]
    start = (component_page - 1) * 50
    assert re.findall(r"<td>(component-\d+)</td>", html) == [
        f"component-{i:04}" for i in range(start, min(start + 50, 213))
    ]
    assert results.loaded[RpmScanVulnerability] == len(ids)
    assert results.loaded[RpmScanComponent] <= 50
    assert_bounded_selects(results, "rpm_scan_component", "rpm_scan_vulnerability")
    assert not any(".raw" in sql or "scan_metadata" in sql for sql in results.statements)
    assert "FOREIGN" not in html
    assert '3 <small>unique CVEs</small>' in html
    assert '<th class="severity-high">High</th>\n          <td>3</td>' in html
    assert "Details" in html and "Logs" in html and "scan.log" in html
    assert "213 component records" in html and "213 vulnerability records" in html


def test_rpm_pagination_links_preserve_other_table_and_results_anchor(results):
    response = get(results, f"/rpm/{results.rpm_id}?component_page=2&vulnerability_page=3")
    for label, previous, next_page in [
        ("Component pages", "?component_page=1&vulnerability_page=3#results", "?component_page=3&vulnerability_page=3#results"),
        ("Vulnerability pages", "?component_page=2&vulnerability_page=2#results", "?component_page=2&vulnerability_page=4#results"),
    ]:
        navigation = re.search(rf'<nav class="pagination" aria-label="{label}">(.*?)</nav>', response.text, re.S)
        assert navigation is not None
        links = [unescape(link) for link in re.findall(r'href="([^"]+)"', navigation.group(1))]
        assert links == [previous, next_page]
        assert all(get(results, f"/rpm/{results.rpm_id}{link}").status_code == 200 for link in links)


@pytest.mark.parametrize("page,expected_links", [(1, ["Next"]), (5, ["Previous"])])
def test_rpm_first_and_last_pages_only_link_to_available_neighbours(results, page, expected_links):
    response = get(results, f"/rpm/{results.rpm_id}?component_page={page}&vulnerability_page={page}")
    for label in ("Component pages", "Vulnerability pages"):
        navigation = re.search(rf'<nav class="pagination" aria-label="{label}">(.*?)</nav>', response.text, re.S)
        assert navigation is not None
        assert re.findall(r">(Previous|Next)</a>", navigation.group(1)) == expected_links


def test_empty_rpm_task_keeps_original_empty_messages_and_logs_section(results):
    response = get(results, f"/rpm/{results.empty_rpm_id}")
    assert response.status_code == 200
    for text in ("Details", "Results", "Logs", "No component data.", "No vulnerabilities found."):
        assert text in response.text
    assert 'class="pagination"' not in response.text
    assert results.loaded[RpmScanComponent] == results.loaded[RpmScanVulnerability] == 0


@pytest.mark.parametrize("query", ["component_page=0", "vulnerability_page=-1", "vulnerability_page=x"])
def test_invalid_rpm_pagination_rejected_before_sql(results, query):
    response = get(results, f"/rpm/{results.rpm_id}?{query}")
    assert response.status_code == 422
    assert results.statements == []


@pytest.mark.parametrize("configured_size,expected", [(1000, 200), (0, 1)])
def test_rpm_detail_page_size_has_a_fixed_upper_bound(results, monkeypatch, settings, configured_size, expected):
    monkeypatch.setattr(rpm_web, "get_settings", lambda: replace(settings, page_size=configured_size))
    response = get(results, f"/rpm/{results.rpm_id}")
    assert response.status_code == 200
    assert results.loaded[RpmScanVulnerability] == expected
    assert results.loaded[RpmScanComponent] == expected


def test_rpm_vulnerability_traversal_is_stable_for_equal_sort_keys(results):
    ids = []
    for page in range(1, 6):
        response = get(results, f"/rpm/{results.rpm_id}?vulnerability_page={page}")
        assert response.status_code == 200
        ids.extend(int(value) for value in re.findall(r'id="evidence-(\d+)"', response.text))
    assert ids == results.vulnerabilities
    assert len(set(ids)) == 213


@pytest.mark.parametrize("page", [999, 10 ** 30])
def test_out_of_range_rpm_pages_have_empty_tables_and_working_return_links(results, page):
    response = get(results, f"/rpm/{results.rpm_id}?component_page={page}&vulnerability_page={page}")
    assert response.status_code == 200
    assert "No vulnerabilities on this page." in response.text
    assert "No component data on this page." in response.text
    assert "No vulnerabilities found." not in response.text
    assert results.loaded[RpmScanVulnerability] == results.loaded[RpmScanComponent] == 0
    assert f'href="?component_page=5&amp;vulnerability_page={page}#results"' in response.text
