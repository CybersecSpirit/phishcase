from fastapi import APIRouter, Depends

from backend.api.endpoints import analyze, cache, lookup, status, submit
from backend.investigation.auth import require_user, require_writer

api_router = APIRouter(dependencies=[Depends(require_user)])
api_router.include_router(
    analyze.router,
    prefix="/analyze",
    tags=["analyze"],
    dependencies=[Depends(require_writer)],
)
api_router.include_router(
    submit.router,
    prefix="/submit",
    tags=["submit"],
    dependencies=[Depends(require_writer)],
)
api_router.include_router(lookup.router, prefix="/lookup", tags=["lookup"])
api_router.include_router(cache.router, prefix="/cache", tags=["cache"])
api_router.include_router(status.router, prefix="/status", tags=["status"])
