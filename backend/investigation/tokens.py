"""Revocable ingestion API tokens, hashed at rest and shown only once."""

import hashlib
import secrets
import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from .auth import User, Writer
from .store import audit, db

router = APIRouter()


def initialize_tokens(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS api_tokens (
        id TEXT PRIMARY KEY, digest TEXT NOT NULL UNIQUE,
        user_id INTEGER NOT NULL REFERENCES users(id), name TEXT NOT NULL,
        created_at REAL NOT NULL, expires REAL NOT NULL)""")


class TokenInput(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    days: int = Field(default=30, ge=1, le=365)


@router.post("/auth/tokens", status_code=201)
def create_token(data: TokenInput, user: Writer):
    if user.get("api_token"):
        raise HTTPException(403, "Use an interactive session to create tokens")
    token = "pc_" + secrets.token_urlsafe(32)
    token_id = secrets.token_hex(16)
    with db() as conn:
        conn.execute(
            "INSERT INTO api_tokens VALUES (?,?,?,?,?,?)",
            (
                token_id,
                hashlib.sha256(token.encode()).hexdigest(),
                user["id"],
                data.name,
                time.time(),
                time.time() + data.days * 86400,
            ),
        )
        audit(conn, user["id"], "api_token.created", detail=token_id)
    return {"id": token_id, "token": token, "expires_in_days": data.days}


@router.get("/auth/tokens")
def list_tokens(user: User):
    with db() as conn:
        return [
            dict(row)
            for row in conn.execute(
                "SELECT id,name,created_at,expires FROM api_tokens WHERE user_id=?",
                (user["id"],),
            )
        ]


@router.delete("/auth/tokens/{token_id}")
def revoke_token(token_id: str, user: User):
    with db() as conn:
        conn.execute(
            "DELETE FROM api_tokens WHERE id=? AND user_id=?", (token_id, user["id"])
        )
        audit(conn, user["id"], "api_token.revoked", detail=token_id)
    return {"ok": True}
