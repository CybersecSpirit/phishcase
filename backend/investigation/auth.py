import hashlib
import os
import secrets
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
            """SELECT u.id,u.username,u.role,u.active,(u.mfa_secret IS NOT NULL) AS mfa_enabled FROM sessions s
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


def csrf(request: Request):
    if request.headers.get("x-requested-with") != "EML-Investigation":
        raise HTTPException(403, "En-tête de protection CSRF requis")


def digest(value: str):
    return hashlib.sha256(value.encode()).hexdigest()


def issue_session(conn, user, response):
    token = secrets.token_urlsafe(32)
    now = time.time()
    conn.execute("DELETE FROM sessions WHERE expires<=?", (now,))
    conn.execute(
        "INSERT INTO sessions VALUES (?,?,?)", (digest(token), user["id"], now + 28800)
    )
    response.headers["Cache-Control"] = "no-store"
    response.set_cookie(
        "eml_session",
        token,
        httponly=True,
        secure=secure_cookie(),
        samesite="strict",
        max_age=28800,
    )
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "mfa_enabled": bool(user["mfa_secret"]),
    }


def throttle(conn, identity, limit=10):
    now = time.time()
    attempt = conn.execute(
        "SELECT * FROM login_attempts WHERE identity=?", (identity,)
    ).fetchone()
    if attempt and now - attempt["window"] < 900 and attempt["count"] >= limit:
        raise HTTPException(429, "Trop de tentatives. Réessayer dans 15 minutes.")
    if not attempt or now - attempt["window"] >= 900:
        conn.execute(
            "INSERT OR REPLACE INTO login_attempts VALUES (?,1,?)", (identity, now)
        )
    else:
        conn.execute(
            "UPDATE login_attempts SET count=count+1 WHERE identity=?", (identity,)
        )


def revoke_auth(conn, user_id):
    for table in ("sessions", "mfa_challenges", "mfa_pending"):
        conn.execute(f"DELETE FROM {table} WHERE user_id=?", (user_id,))
