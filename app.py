"""FastAPI entry point - app creation, route mounting, startup hooks."""
import logging
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI

from auth import seed_admin
from config import settings
from db import init_db
from oidc import router as oidc_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sso")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # TODO: P0 init_db() + seed_admin()
    yield


def _create_app() -> FastAPI:
    app = FastAPI(title="SSO OIDC Service", docs_url="/docs", lifespan=lifespan)
    app.include_router(oidc_router)
    return app


app = _create_app()


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run("app:app", host=settings.host, port=settings.port, reload=True)
