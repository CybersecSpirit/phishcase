import hashlib
import os
import time
from typing import Annotated

from fastapi import Depends, HTTPException, Request

from .store import db


def require_user(request: Request):
    # A custom header forces a CORS preflight for cross-origin writes. No CORS origins are enabled.
    if (
        request.method not in ("GET", "HEAD", "OPTIONS")
        and request.headers.get("x-requested-with") != "EML-Investigation"
    ):
        raise HTTPException(403, "En-tête de protection CSRF requis")
    token = request.cookies.get("eml_session", "")
    with db() as conn:
        user = conn.execute(
            """SELECT u.id,u.username,u.role,u.active FROM sessions s
            JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>? AND u.active=1""",
            (hashlib.sha256(token.encode()).hexdigest(), time.time()),
        ).fetchone()
    if not user:
        raise HTTPException(401, "Authentification requise")
    return dict(user)


User = Annotated[dict, Depends(require_user)]


def require_writer(user: User):
    if user["role"] not in ("admin", "analyst"):
        raise HTTPException(403, "Droits analyste requis")
    return user


Writer = Annotated[dict, Depends(require_writer)]


def require_admin(user: User):
    if user["role"] != "admin":
        raise HTTPException(403, "Droits administrateur requis")
    return user


Admin = Annotated[dict, Depends(require_admin)]


def secure_cookie():
    return os.environ.get("COOKIE_SECURE", "true").lower() != "false"
