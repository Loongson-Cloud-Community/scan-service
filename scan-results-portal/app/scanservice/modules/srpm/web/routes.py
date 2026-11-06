from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from ....config import get_settings
from ....db import get_db
from ..services.task_queries import get_task_detail, list_task_web_page
from ..services.task_service import (
    detail_values,
    format_timestamp,
    scan_method,
)


router = APIRouter(tags=["srpm-web"])
templates = Jinja2Templates(directory="/app/scanservice/templates")
templates.env.filters["timestamp"] = format_timestamp
templates.env.filters["scan_method"] = scan_method


@router.get("/srpm", response_class=HTMLResponse)
def tasks_page(
    request: Request,
    search: str | None = None,
    scan_result: str | None = None,
    page: int = Query(1, ge=1),
    db: Session = Depends(get_db),
) -> HTMLResponse:
    settings = get_settings()
    total, rows = list_task_web_page(db, search, scan_result, page, settings.page_size)
    return templates.TemplateResponse(
        "srpm/tasks.html",
        {
            "request": request,
            "title": settings.title,
            "tasks": rows,
            "total": total,
            "page": page,
            "page_size": settings.page_size,
            "search": search or "",
            "scan_result": scan_result or "",
        },
    )


@router.get("/srpm/{task_id}", response_class=HTMLResponse)
def task_page(
    request: Request, task_id: int, db: Session = Depends(get_db)
) -> HTMLResponse:
    settings = get_settings()
    task = get_task_detail(db, task_id)
    return templates.TemplateResponse(
        "srpm/task_detail.html",
        {
            "request": request,
            "title": settings.title,
            "task": task,
            "details": detail_values(task),
        },
    )
