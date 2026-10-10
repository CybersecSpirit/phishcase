import os
import time
from contextlib import asynccontextmanager

import fastapi_csp_docs
from fastapi import FastAPI
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from loguru import logger
from redis.asyncio import Redis
from Secweb.headers import Content_Security_Policy
from starlette.exceptions import HTTPException as StarletteHTTPException

from backend import settings
from backend.investigation.api import router as investigation_router
from backend.investigation.evidence import storage
from backend.investigation.http_security import SecurityMiddleware
from backend.investigation.readiness import storage_ready
from backend.investigation.store import db, initialize


@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize()
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


class SPAFiles(StaticFiles):
    async def get_response(self, path, scope):
        try:
            return await super().get_response(path, scope)
        except StarletteHTTPException as exc:
            if (
                exc.status_code == 404
                and scope["method"] in {"GET", "HEAD"}
                and not path.startswith(("api/", "assets/"))
                and "." not in path.rsplit("/", 1)[-1]
            ):
                return await super().get_response("index.html", scope)
            raise


def create_app():
    logger.remove()
    logger.add(
        settings.LOG_FILE,
        level=settings.LOG_LEVEL,
        backtrace=False,
        diagnose=False,
        serialize=True,
    )

    app = FastAPI(
        debug=settings.DEBUG,
        title=settings.PROJECT_NAME,
        version="1.0.0rc1",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )
    # add middleware
    app.add_middleware(GZipMiddleware, minimum_size=1000)
    app.add_middleware(SecurityMiddleware)
    if os.environ.get("ENABLE_API_DOCS", "false") == "true":
        fastapi_csp_docs.setup(app)

    Content_Security_Policy(
        app,
        options={
            "default-src": ["'self'"],
            "base-uri": ["'self'"],
            "block-all-mixed-content": [],
            "font-src": ["'self'", "data:"],
            "frame-ancestors": ["'self'"],
            "img-src": ["'self'", "data:"],
            "object-src": ["'none'"],
            "script-src": [
                "'self'",
                "https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js",
                "https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js",
            ],
            "worker-src": ["'self'", "blob:"],
            "script-src-attr": ["'none'"],
            "style-src": ["'self'", "'unsafe-inline'"],
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
    app.include_router(
        investigation_router, prefix="/api/v1", tags=["PhishCase API v1"]
    )

    # Historical synchronous endpoints are no longer mounted in the product.
    # Ingestion always uses the durable queue, via /api/v1/analyses.
    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/ready")
    def ready():
        healthy = False
        try:
            with db() as conn:
                conn.execute("SELECT 1")
                recent = conn.execute(
                    "SELECT max(seen) FROM worker_heartbeats"
                ).fetchone()[0]
            root = storage().root
            healthy = storage_ready(root) and bool(
                recent and recent > time.time() - 300
            )
        except Exception:
            pass
        return JSONResponse(
            {"status": "ready" if healthy else "not_ready"},
            status_code=200 if healthy else 503,
        )

    app.mount("/", SPAFiles(html=True, directory="frontend/dist/"), name="index")

    return app


app = create_app()
