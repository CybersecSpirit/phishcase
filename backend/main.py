from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from loguru import logger
from redis.asyncio import Redis
from Secweb.ContentSecurityPolicy import ContentSecurityPolicy

from backend import settings
from backend.api.api import api_router
from backend.investigation.api import router as investigation_router
from backend.investigation.store import db, initialize


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize()
    with db() as conn:
        conn.execute(
            "UPDATE analyses SET status='failed', error='Service redémarré pendant cette analyse ; importer à nouveau le fichier.', finished_at=CURRENT_TIMESTAMP WHERE status IN ('running','queued')"
        )
    app.state.redis = (
        Redis.from_url(str(settings.REDIS_URL)) if settings.REDIS_URL else None
    )
    try:
        yield
    finally:
        if app.state.redis is not None:
            await app.state.redis.aclose()


def create_app():
    logger.add(
        settings.LOG_FILE, level=settings.LOG_LEVEL, backtrace=settings.LOG_BACKTRACE
    )

    app = FastAPI(
        debug=settings.DEBUG,
        title=settings.PROJECT_NAME,
        lifespan=lifespan,
    )
    # add middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    app.add_middleware(
        ContentSecurityPolicy,
        Option={"img-src": ["'self'", "data:", "t0.gstatic.com", "www.google.com"]},
        script_nonce=False,
        style_nonce=False,
        report_only=False,
    )

    # add routes
    app.include_router(
        investigation_router, prefix="/api/workspace", tags=["PhishCase"]
    )
    app.include_router(api_router, prefix="/api")
    app.mount("/", StaticFiles(html=True, directory="frontend/dist/"), name="index")

    return app


app = create_app()
