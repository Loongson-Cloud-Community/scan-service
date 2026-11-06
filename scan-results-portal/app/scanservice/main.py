from __future__ import annotations

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from .api.health import router as health_router
from .config import get_settings
from .modules.rpm.api.routes import router as rpm_api_router
from .modules.rpm.web.routes import router as rpm_web_router
from .modules.srpm.api.routes import router as srpm_api_router
from .modules.srpm.web.routes import router as srpm_web_router


settings = get_settings()
app = FastAPI(title=settings.title)
app.mount("/static", StaticFiles(directory="/app/scanservice/static"), name="static")

app.include_router(health_router)
app.include_router(srpm_api_router)
app.include_router(rpm_api_router)
app.include_router(srpm_web_router)
app.include_router(rpm_web_router)
