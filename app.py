"""FastAPI entry point - app creation, route mounting, startup hooks."""
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

from admin import router as admin_router
from auth import seed_admin
from config import settings
from db import init_db
from oidc import router as oidc_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sso")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_admin()
    logger.info("SSO service started on %s:%s", settings.host, settings.port)
    logger.info("Issuer: %s", settings.issuer_url)
    logger.info("DB: %s", settings.db_path)
    yield


def _create_app() -> FastAPI:
    app = FastAPI(title="SSO OIDC Service", docs_url="/docs", lifespan=lifespan)
    app.include_router(oidc_router)
    app.include_router(admin_router)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'unsafe-inline'"
        return response

    return app


app = _create_app()

app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, max_age=settings.session_max_age)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
async def index(request: Request):
    uid = request.session.get("uid")
    if uid is None:
        return RedirectResponse("/admin/login", status_code=303)
    if request.session.get("is_admin"):
        return RedirectResponse("/admin/", status_code=303)
    return RedirectResponse("/admin/account", status_code=303)


if __name__ == "__main__":
    uvicorn.run("app:app", host=settings.host, port=settings.port, reload=True)
