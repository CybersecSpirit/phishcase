from contextlib import asynccontextmanager

import fastapi_csp_docs
from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from loguru import logger
from redis.asyncio import Redis
from Secweb.headers import Content_Security_Policy

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
        Redis.from_url(str(settings.REDIS_URL), legacy_responses=False)
        if settings.REDIS_URL
        else None
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
        docs_url=None,
        redoc_url=None,
    )
    # add middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    fastapi_csp_docs.setup(app)

    Content_Security_Policy(
        app,
        options={
            "default-src": ["'self'"],
            "base-uri": ["'self'"],
            "block-all-mixed-content": [],
            "font-src": ["'self'", "https:", "data:"],
            "frame-ancestors": ["'self'"],
            "img-src": ["'self'", "data:", "t0.gstatic.com", "www.google.com"],
            "object-src": ["'none'"],
            "script-src": [
                "'self'",
                "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
                "https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js",
            ],
            "worker-src": ["'self'", "blob:"],
            "script-src-attr": ["'none'"],
            "style-src": ["'self'", "https:", "'unsafe-inline'"],
            "upgrade-insecure-requests": [],
        },
        script_nonce_flag=False,
        style_nonce_flag=False,
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
