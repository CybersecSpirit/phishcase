"""Optional TOTP MFA: encrypted enrollment, password-bound challenges and single-use recovery."""

import base64
import os
import secrets
import time
from pathlib import Path

import pyotp
import qrcode
import qrcode.image.svg
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .auth import (
    User,
    csrf,
    digest,
    issue_session,
    revoke_auth,
    secure_cookie,
    throttle,
)
from .store import audit, db, password_matches


def no_store(response: Response):
    response.headers["Cache-Control"] = "no-store"


router = APIRouter(prefix="/auth/mfa", dependencies=[Depends(csrf), Depends(no_store)])


class Password(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class Code(BaseModel):
    code: str = Field(min_length=1, max_length=64)


class Proof(Password, Code):
    pass


def cipher(conn):
    """Serialize first key creation under the caller's SQLite write transaction."""
    key = os.environ.get("MFA_ENCRYPTION_KEY")
    if not key:
        path = Path(
            os.environ.get("INVESTIGATION_DB", "data/investigation.sqlite3")
            + ".mfa.key"
        )
        if not path.exists():
            if (
                conn.execute(
                    "SELECT 1 FROM users WHERE mfa_secret IS NOT NULL LIMIT 1"
                ).fetchone()
                or conn.execute("SELECT 1 FROM mfa_pending LIMIT 1").fetchone()
            ):
                raise HTTPException(
                    503,
                    "Clé MFA indisponible. Contacter l'administrateur de l'installation.",
                )
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(Fernet.generate_key())
            except FileExistsError:
                pass
        try:
            key = path.read_bytes()
        except OSError as exc:
            raise HTTPException(503, "Clé MFA indisponible.") from exc
    try:
        return Fernet(key)
    except (ValueError, TypeError) as exc:
        raise HTTPException(503, "Configuration du chiffrement MFA invalide.") from exc


def decrypt(conn, encrypted):
    try:
        return cipher(conn).decrypt(encrypted.encode()).decode()
    except InvalidToken as exc:
        raise HTTPException(
            503, "Clé MFA incorrecte. Restaurer la clé de cette installation."
        ) from exc


def begin_challenge(conn, user, request, response):
    token = secrets.token_urlsafe(32)
    conn.execute(
        "DELETE FROM mfa_challenges WHERE expires<=? OR user_id=?",
        (time.time(), user["id"]),
    )
    conn.execute(
        "INSERT INTO mfa_challenges VALUES (?,?,?)",
        (digest(token), user["id"], time.time() + 300),
    )
    # Even an already authenticated browser must finish this new login.
    conn.execute(
        "DELETE FROM sessions WHERE token=?",
        (digest(request.cookies.get("eml_session", "")),),
    )
    response.delete_cookie(
        "eml_session", secure=secure_cookie(), httponly=True, samesite="strict"
    )
    response.set_cookie(
        "eml_mfa",
        token,
        httponly=True,
        secure=secure_cookie(),
        samesite="strict",
        max_age=300,
    )
    response.headers["Cache-Control"] = "no-store"
    return {"mfa_required": True}


def match_step(secret, code, last=-1):
    if len(code) != 6 or not code.isascii() or not code.isdigit():
        return None
    current = int(time.time()) // 30
    totp = pyotp.TOTP(secret)
    for step in (current, current - 1, current + 1):
        if step > last and secrets.compare_digest(totp.at(step * 30), code):
            return step
    return None


def consume_factor(conn, user, code):
    code = code.strip()
    # Recovery remains usable even if the deployment encryption key was lost.
    recovery = digest(code.replace("-", "").replace(" ", "").lower())
    removed = conn.execute(
        "DELETE FROM mfa_recovery WHERE user_id=? AND digest=?", (user["id"], recovery)
    ).rowcount
    if removed:
        audit(conn, user["id"], "mfa.recovery_used")
        return True
    step = match_step(decrypt(conn, user["mfa_secret"]), code, user["mfa_last_step"])
    if step is None:
        return False
    conn.execute("UPDATE users SET mfa_last_step=? WHERE id=?", (step, user["id"]))
    return True


def recovery_codes(conn, user_id):
    codes = []
    for _ in range(10):
        raw = secrets.token_hex(10)
        codes.append("-".join(raw[i : i + 5] for i in range(0, 20, 5)))
    conn.execute("DELETE FROM mfa_recovery WHERE user_id=?", (user_id,))
    conn.executemany(
        "INSERT INTO mfa_recovery VALUES (?,?)",
        [(user_id, digest(code.replace("-", ""))) for code in codes],
    )
    return codes


def current_user(conn, request, user):
    # Recheck under the write lock: a revoked session cannot enroll/disable MFA in a race.
    row = conn.execute(
        """SELECT u.* FROM users u JOIN sessions s ON s.user_id=u.id
        WHERE u.id=? AND u.active=1 AND s.token=? AND s.expires>?""",
        (user["id"], digest(request.cookies.get("eml_session", "")), time.time()),
    ).fetchone()
    if not row:
        raise HTTPException(401, "Authentification requise")
    return row


def check_password(conn, user, password):
    throttle(conn, f"manage:{user['id']}", 5)
    if not password_matches(password, user["password"]):
        conn.commit()
        raise HTTPException(
            400, "Vérification refusée : mot de passe ou code invalide."
        )


def check_proof(conn, user, data):
    check_password(conn, user, data.password)
    if not user["mfa_secret"]:
        raise HTTPException(409, "Le MFA n'est pas activé.")
    throttle(conn, f"mfa:{user['id']}", 5)
    if not consume_factor(conn, user, data.code):
        conn.commit()
        raise HTTPException(
            400, "Code invalide ou déjà utilisé. Attendez le prochain code."
        )


def clear_attempts(conn, user_id):
    conn.execute(
        "DELETE FROM login_attempts WHERE identity IN (?,?)",
        (f"manage:{user_id}", f"mfa:{user_id}"),
    )


@router.post("/verify")
def verify(data: Code, request: Request, response: Response):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        challenge = conn.execute(
            "SELECT * FROM mfa_challenges WHERE token=? AND expires>?",
            (digest(request.cookies.get("eml_mfa", "")), time.time()),
        ).fetchone()
        if not challenge:
            raise HTTPException(401, "Vérification expirée. Recommencez la connexion.")
        user = conn.execute(
            "SELECT * FROM users WHERE id=? AND active=1 AND mfa_secret IS NOT NULL",
            (challenge["user_id"],),
        ).fetchone()
        if not user:
            raise HTTPException(401, "Recommencez la connexion.")
        throttle(conn, f"mfa:{user['id']}", 5)
        if not consume_factor(conn, user, data.code):
            conn.commit()
            raise HTTPException(
                400, "Code invalide ou déjà utilisé. Attendez le prochain code."
            )
        conn.execute("DELETE FROM mfa_challenges WHERE user_id=?", (user["id"],))
        clear_attempts(conn, user["id"])
        audit(conn, user["id"], "login.mfa")
        response.delete_cookie(
            "eml_mfa", secure=secure_cookie(), httponly=True, samesite="strict"
        )
        return issue_session(conn, user, response)


@router.get("")
def status(user: User):
    with db() as conn:
        remaining = conn.execute(
            "SELECT count(*) FROM mfa_recovery WHERE user_id=?", (user["id"],)
        ).fetchone()[0]
    return {"enabled": bool(user["mfa_enabled"]), "recovery_remaining": remaining}


@router.post("/setup")
def setup(data: Password, request: Request, user: User):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = current_user(conn, request, user)
        if current["mfa_secret"]:
            raise HTTPException(409, "Le MFA est déjà activé.")
        check_password(conn, current, data.password)
        secret = pyotp.random_base32()
        encrypted = cipher(conn).encrypt(secret.encode()).decode()
        conn.execute("DELETE FROM mfa_pending WHERE expires<=?", (time.time(),))
        conn.execute(
            "INSERT OR REPLACE INTO mfa_pending VALUES (?,?,?,?)",
            (
                user["id"],
                encrypted,
                digest(request.cookies.get("eml_session", "")),
                time.time() + 600,
            ),
        )
        # Do not clear enrollment failures by issuing a new seed.
        uri = pyotp.TOTP(secret).provisioning_uri(
            name=user["username"], issuer_name="PhishCase"
        )
        svg = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage).to_string()
        return {
            "secret": secret,
            "qr": "data:image/svg+xml;base64," + base64.b64encode(svg).decode(),
            "expires_in": 600,
        }


@router.post("/enable")
def enable(data: Code, request: Request, response: Response, user: User):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = current_user(conn, request, user)
        if current["mfa_secret"]:
            raise HTTPException(409, "Le MFA est déjà activé.")
        pending = conn.execute(
            "SELECT * FROM mfa_pending WHERE user_id=? AND session_token=? AND expires>?",
            (user["id"], digest(request.cookies.get("eml_session", "")), time.time()),
        ).fetchone()
        if not pending:
            raise HTTPException(400, "Configuration expirée. Recommencez l'activation.")
        throttle(conn, f"mfa:{user['id']}", 5)
        step = match_step(decrypt(conn, pending["secret"]), data.code.strip())
        if step is None:
            conn.commit()
            raise HTTPException(
                400, "Code invalide. Vérifiez l'heure de votre application."
            )
        conn.execute(
            "UPDATE users SET mfa_secret=?,mfa_last_step=? WHERE id=?",
            (pending["secret"], step, user["id"]),
        )
        codes = recovery_codes(conn, user["id"])
        revoke_auth(conn, user["id"])
        clear_attempts(conn, user["id"])
        issue_session(conn, current, response)
        audit(conn, user["id"], "mfa.enabled")
        return {"recovery_codes": codes}


@router.post("/cancel")
def cancel(request: Request, user: User):
    with db() as conn:
        conn.execute(
            "DELETE FROM mfa_pending WHERE user_id=? AND session_token=?",
            (user["id"], digest(request.cookies.get("eml_session", ""))),
        )
    return {"ok": True}


@router.post("/recovery")
def regenerate(data: Proof, request: Request, response: Response, user: User):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = current_user(conn, request, user)
        check_proof(conn, current, data)
        codes = recovery_codes(conn, user["id"])
        revoke_auth(conn, user["id"])
        clear_attempts(conn, user["id"])
        issue_session(conn, current, response)
        audit(conn, user["id"], "mfa.recovery_regenerated")
        return {"recovery_codes": codes}


@router.post("/disable")
def disable(data: Proof, request: Request, response: Response, user: User):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = current_user(conn, request, user)
        check_proof(conn, current, data)
        conn.execute(
            "UPDATE users SET mfa_secret=NULL,mfa_last_step=-1 WHERE id=?",
            (user["id"],),
        )
        conn.execute("DELETE FROM mfa_recovery WHERE user_id=?", (user["id"],))
        revoke_auth(conn, user["id"])
        clear_attempts(conn, user["id"])
        issue_session(conn, current, response)
        audit(conn, user["id"], "mfa.disabled")
    return {"ok": True}
