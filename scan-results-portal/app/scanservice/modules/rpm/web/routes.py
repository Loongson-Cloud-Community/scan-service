from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ....config import get_settings
from ....db import get_db
from ..services.task_queries import (
    get_task_detail, list_task_components_page, list_task_vulnerabilities_page,
    list_task_web_page,
)
from ..services.task_service import format_timestamp


router = APIRouter(tags=["rpm-web"])
templates = Jinja2Templates(directory="/app/scanservice/templates")
templates.env.filters["timestamp"] = format_timestamp


@router.get("/rpm", response_class=HTMLResponse)
def tasks_page(
    request: Request,
    search: str | None = None,
    state: str | None = None,
    page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    settings = get_settings()
    total, tasks = list_task_web_page(db, search, state, page, settings.page_size)
    return templates.TemplateResponse(
        "rpm/tasks.html",
        {
            "request": request,
            "title": settings.title,
            "tasks": tasks,
            "total": total,
            "page": page,
            "page_size": settings.page_size,
            "search": search or "",
            "state": state or "",
        },
    )


@router.get("/rpm/{task_id}", response_class=HTMLResponse)
def task_page(
    request: Request,
    task_id: int,
    component_page: int = Query(1, ge=1),
    vulnerability_page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    settings = get_settings()
    task = get_task_detail(db, task_id)
    page_size = min(max(settings.page_size, 1), 200)
    component_total, components = list_task_components_page(db, task_id, component_page, page_size)
    vulnerability_total, vulnerabilities = list_task_vulnerabilities_page(
        db, task_id, vulnerability_page, page_size,
    )
    return templates.TemplateResponse(
        "rpm/task_detail.html",
        {
            "request": request,
            "title": settings.title,
            "task": task,
            "components": components,
            "vulnerabilities": vulnerabilities,
            "component_total": component_total,
            "vulnerability_total": vulnerability_total,
            "component_page": component_page,
            "vulnerability_page": vulnerability_page,
            "component_pages": max(1, (component_total + page_size - 1) // page_size),
            "vulnerability_pages": max(1, (vulnerability_total + page_size - 1) // page_size),
            "page_size": page_size,
        },
    )
