import base64
import hashlib
import json
import sqlite3
from typing import Literal
from urllib.parse import quote

from fastapi import APIRouter, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field

from .assessment import summarize
from .auth import (
    Admin,
    User,
    Writer,
    csrf,
    issue_session,
    revoke_auth,
    secure_cookie,
    throttle,
)
from .dkim_api import router as dkim_router
from .enrichment_api import router as enrichment_router
from .exports import router as exports_router
from .investigations import router as investigations_router
from .mfa import begin_challenge
from .mfa import router as mfa_router
from .store import audit, db, password_hash, password_matches
from .tokens import router as tokens_router

router = APIRouter()
router.include_router(mfa_router)

router.include_router(tokens_router)
router.include_router(exports_router)
router.include_router(enrichment_router)
router.include_router(dkim_router)
router.include_router(investigations_router)


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=80, pattern=r"^[a-zA-Z0-9_.@-]+$")
    password: str = Field(min_length=1, max_length=256)


class NewUser(Login):
    password: str = Field(min_length=12, max_length=256)
    role: Literal["admin", "analyst", "viewer"] = "analyst"


class UserUpdate(BaseModel):
    role: Literal["admin", "analyst", "viewer"]
    active: bool
    password: str | None = Field(default=None, min_length=12, max_length=256)


class CaseInput(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=20000)
    status: Literal["open", "investigating", "resolved", "closed"] = "open"
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    assignee_id: int | None = None


class Note(BaseModel):
    body: str = Field(min_length=1, max_length=20000)


class Verdict(BaseModel):
    verdict: Literal["unreviewed", "benign", "suspicious", "malicious"]


def case_exists(conn, case_id):
    row = conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Dossier introuvable")
    return dict(row)


def validate_assignee(conn, user_id):
    if (
        user_id is not None
        and not conn.execute(
            "SELECT id FROM users WHERE id=? AND active=1 AND role IN ('admin','analyst')",
            (user_id,),
        ).fetchone()
    ):
        raise HTTPException(422, "Responsable invalide")


@router.post("/auth/login")
def login(data: Login, request: Request, response: Response):
    csrf(request)
    identity = data.username.lower()
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        throttle(conn, identity)
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (data.username,)
        ).fetchone()
        valid = password_matches(
            data.password,
            user["password"] if user else password_hash("invalid-password", "00" * 16),
        )
        if not user or not valid or not user["active"]:
            conn.commit()  # Failed attempts must survive the HTTP error.
            raise HTTPException(401, "Identifiants invalides")
        conn.execute("DELETE FROM login_attempts WHERE identity=?", (identity,))
        if user["mfa_secret"]:
            # A correct password is only a first step, never a full session.
            return begin_challenge(conn, user, request, response)
        audit(conn, user["id"], "login")
        return issue_session(conn, user, response)


@router.get("/auth/me")
def me(user: User):
    return user


@router.post("/auth/logout")
def logout(request: Request, response: Response, user: User):
    with db() as conn:
        conn.execute(
            "DELETE FROM sessions WHERE token=?",
            (
                hashlib.sha256(
                    request.cookies.get("eml_session", "").encode()
                ).hexdigest(),
            ),
        )
    response.delete_cookie(
        "eml_session", secure=secure_cookie(), httponly=True, samesite="strict"
    )
    return {"ok": True}


@router.get("/users")
def users(user: User):
    with db() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT id,username,role,active,created_at,(mfa_secret IS NOT NULL) AS mfa_enabled FROM users ORDER BY username"
            )
        ]


@router.post("/users", status_code=201)
def add_user(data: NewUser, user: Admin):
    with db() as conn:
        try:
            cursor = conn.execute(
                "INSERT INTO users(username,password,role) VALUES (?,?,?)",
                (data.username, password_hash(data.password), data.role),
            )
        except sqlite3.IntegrityError as exc:
            raise HTTPException(409, "Identifiant déjà utilisé") from exc
        audit(conn, user["id"], "user.created", detail=data.username)
        return {"id": cursor.lastrowid}


@router.put("/users/{user_id}")
def update_user(user_id: int, data: UserUpdate, user: Admin):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            raise HTTPException(404, "Compte introuvable")
        if user_id == user["id"] and (not data.active or data.role != "admin"):
            raise HTTPException(
                409, "Impossible de retirer vos propres droits administrateur"
            )
        conn.execute(
            "UPDATE users SET role=?,active=? WHERE id=?",
            (data.role, data.active, user_id),
        )
        if data.password:
            conn.execute(
                "UPDATE users SET password=? WHERE id=?",
                (password_hash(data.password), user_id),
            )
        revoke_auth(conn, user_id)
        audit(conn, user["id"], "user.updated", detail=target["username"])
    return {"ok": True}


@router.get("/config")
def workspace_configuration():
    """Public presentation extension point; commercial adapters may replace it."""
    return {"navigation": [], "auth_links": [], "manage_users_url": None}


@router.get("/dashboard")
def dashboard(user: User):
    with db() as conn:
        return {
            "cases": conn.execute("SELECT count(*) FROM cases").fetchone()[0],
            "open_cases": conn.execute(
                "SELECT count(*) FROM cases WHERE status IN ('open','investigating')"
            ).fetchone()[0],
            "analyses": conn.execute("SELECT count(*) FROM analyses").fetchone()[0],
            "iocs": conn.execute("SELECT count(*) FROM iocs").fetchone()[0],
            "failed_analyses": conn.execute(
                "SELECT count(*) FROM analyses WHERE status='failed'"
            ).fetchone()[0],
            "pending_verdicts": conn.execute(
                """SELECT count(*) FROM analyses a WHERE a.status='completed' AND
                COALESCE((SELECT action FROM analyst_decisions d WHERE d.analysis_id=a.id ORDER BY d.id DESC LIMIT 1),'reopened')='reopened'"""
            ).fetchone()[0],
            "active_campaigns": conn.execute(
                "SELECT count(*) FROM campaigns WHERE status='active' AND deleted_at IS NULL"
            ).fetchone()[0],
            "frequent_iocs": [
                dict(row)
                for row in conn.execute(
                    """SELECT i.id,i.kind,i.value,count(DISTINCT a.id) AS analysis_count,
                count(DISTINCT a.case_id) AS case_count FROM iocs i
                JOIN analysis_iocs ai ON ai.ioc_id=i.id JOIN analyses a ON a.id=ai.analysis_id
                GROUP BY i.id ORDER BY analysis_count DESC,i.id DESC LIMIT 10"""
                )
            ],
            "recent_analyses": [
                dict(row)
                for row in conn.execute(
                    "SELECT id,case_id,filename,subject,status,created_at FROM analyses ORDER BY created_at DESC,id DESC LIMIT 10"
                )
            ],
            "priorities": [
                dict(r)
                for r in conn.execute(
                    "SELECT priority,count(*) AS count FROM cases GROUP BY priority"
                )
            ],
            "activity": [
                dict(r)
                for r in conn.execute(
                    "SELECT e.*,u.username FROM events e LEFT JOIN users u ON u.id=e.actor_id ORDER BY e.id DESC LIMIT 30"
                )
            ],
        }


@router.post("/cases", status_code=201)
def create_case(data: CaseInput, user: Writer):
    with db() as conn:
        validate_assignee(conn, data.assignee_id)
        cursor = conn.execute(
            "INSERT INTO cases(title,description,status,priority,assignee_id,created_by) VALUES (?,?,?,?,?,?)",
            (
                data.title,
                data.description,
                data.status,
                data.priority,
                data.assignee_id,
                user["id"],
            ),
        )
        case_id = cursor.lastrowid
        audit(conn, user["id"], "case.created", case_id, data.title)
        return case_exists(conn, case_id)


@router.get("/cases/{case_id}")
def get_case(case_id: int, user: User):
    with db() as conn:
        result = case_exists(conn, case_id)
        result["notes"] = [
            dict(r)
            for r in conn.execute(
                "SELECT n.*,u.username FROM notes n JOIN users u ON u.id=n.author_id WHERE case_id=? ORDER BY n.id DESC",
                (case_id,),
            )
        ]
        result["events"] = [
            dict(r)
            for r in conn.execute(
                "SELECT e.*,u.username FROM events e LEFT JOIN users u ON u.id=e.actor_id WHERE case_id=? ORDER BY e.id DESC LIMIT 200",
                (case_id,),
            )
        ]
        return result


@router.put("/cases/{case_id}")
def update_case(case_id: int, data: CaseInput, user: Writer):
    with db() as conn:
        case_exists(conn, case_id)
        validate_assignee(conn, data.assignee_id)
        conn.execute(
            "UPDATE cases SET title=?,description=?,status=?,priority=?,assignee_id=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (
                data.title,
                data.description,
                data.status,
                data.priority,
                data.assignee_id,
                case_id,
            ),
        )
        audit(conn, user["id"], "case.updated", case_id, data.model_dump_json())
        return case_exists(conn, case_id)


@router.post("/cases/{case_id}/notes", status_code=201)
def add_note(case_id: int, data: Note, user: Writer):
    with db() as conn:
        case_exists(conn, case_id)
        conn.execute(
            "INSERT INTO notes(case_id,author_id,body) VALUES (?,?,?)",
            (case_id, user["id"], data.body),
        )
        audit(conn, user["id"], "note.added", case_id)
    return {"ok": True}


@router.get("/analyses/{analysis_id}")
def get_analysis(analysis_id: str, user: User):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM analyses WHERE id=?", (analysis_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Analyse introuvable")
        result = dict(row)
        result.pop("source", None)
        result.pop("source_ref", None)
        from .failures import error_code

        result["error_code"] = error_code(result.get("error"))
        result["result"] = json.loads(result["result"]) if result["result"] else None
        if result["result"] is not None:
            for item in result["result"].get("eml", {}).get("attachments", []):
                item.pop("raw", None)
            result["assessment"] = result["result"].get("assessment") or summarize(
                result["result"]
            )
            from .report_context import investigation_context

            result["result"]["investigation"] = investigation_context(
                conn, analysis_id, result["result"]
            )
        else:
            result["assessment"] = None
        return result


def extract_iocs(result):
    eml = result.get("eml", {})
    values = set()
    fields = {
        "urls": "url",
        "domains": "domain",
        "emails": "email",
        "ip_addresses": "ip",
    }
    for body in eml.get("bodies", []):
        for field, kind in fields.items():
            values.update(
                (kind, value.strip()) for value in body.get(field, []) if value.strip()
            )
    header = eml.get("header", {})
    for field, kind in [
        ("received_domain", "domain"),
        ("received_ip", "ip"),
        ("received_email", "email"),
    ]:
        values.update(
            (kind, value.strip()) for value in header.get(field) or [] if value.strip()
        )
    for attachment in eml.get("attachments", []):
        digest = attachment.get("hash", {}).get("sha256")
        if digest:
            values.add(("sha256", digest))
    return {
        (kind, value.lower() if kind in ("domain", "sha256") else value)
        for kind, value in values
    }


async def read_email(file: UploadFile) -> tuple[bytes, str]:
    filename = (
        (file.filename or "message.eml").replace("\\", "/").rsplit("/", 1)[-1][:255]
    )
    if not filename.lower().endswith((".eml", ".msg")):
        raise HTTPException(422, "Formats acceptés : EML et MSG")
    raw = await file.read(20 * 1024 * 1024 + 1)
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(413, "Fichier limité à 20 Mo")
    if not raw:
        raise HTTPException(422, "Fichier vide")
    return raw, filename


@router.post("/analyses", status_code=202)
async def direct_upload(file: UploadFile, request: Request, user: Writer):
    return await queue_upload(file, request, user)


@router.post("/cases/{case_id}/analyses", status_code=202)
async def upload(case_id: int, file: UploadFile, request: Request, user: Writer):
    return await queue_upload(file, request, user, case_id)


async def queue_upload(file, request, user, case_id=None):
    from .auth import throttle_user
    from .jobs import enqueue

    throttle_user(user["id"], "uploads", 20)
    raw, filename = await read_email(file)
    try:
        analysis_id = enqueue(
            raw,
            filename,
            user,
            case_id,
            ingestion_source="api" if user.get("api_token") else "upload",
            idempotency_key=request.headers.get("Idempotency-Key"),
        )
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(404, "Dossier introuvable") from exc
    return get_analysis(analysis_id, user)


@router.post("/analyses/{analysis_id}/retry", status_code=202)
def retry_analysis(analysis_id: str, user: Writer):
    import time

    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM analyses WHERE id=?", (analysis_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Analyse introuvable")
        if row["status"] != "failed":
            raise HTTPException(
                409, "Seules les analyses échouées peuvent être relancées"
            )
        conn.execute(
            "UPDATE jobs SET state='queued',attempts=0,error=NULL,available_at=?,lease_token=NULL,lease_until=NULL WHERE analysis_id=?",
            (time.time(), analysis_id),
        )
        conn.execute(
            "UPDATE analyses SET status='queued',error=NULL,finished_at=NULL WHERE id=?",
            (analysis_id,),
        )
        audit(conn, user["id"], "analysis.retried", row["case_id"], analysis_id)
    return get_analysis(analysis_id, user)


@router.put("/iocs/{ioc_id}")
def set_verdict(ioc_id: int, data: Verdict, user: Writer):
    with db() as conn:
        cursor = conn.execute(
            "UPDATE iocs SET verdict=? WHERE id=?", (data.verdict, ioc_id)
        )
        if not cursor.rowcount:
            raise HTTPException(404, "IOC introuvable")
        audit(conn, user["id"], "ioc.reviewed", detail=f"{ioc_id}: {data.verdict}")
    return {"ok": True}


@router.get("/analyses/{analysis_id}/source")
def source(analysis_id: str, user: User):
    from .evidence import original

    with db() as conn:
        row = conn.execute(
            "SELECT filename FROM analyses WHERE id=?", (analysis_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Source indisponible")
        try:
            content = original(conn, analysis_id)
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                409, "Preuve indisponible ou intégrité non vérifiée"
            ) from exc
    suffix = ".msg" if row["filename"].lower().endswith(".msg") else ".eml"
    return Response(
        content=content,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{analysis_id}{suffix}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
        },
    )


@router.get("/analyses/{analysis_id}/attachments/{attachment_index}")
def attachment_source(analysis_id: str, attachment_index: int, user: User):
    from .evidence import storage

    analysis = get_analysis(analysis_id, user)
    attachments = (analysis["result"] or {}).get("eml", {}).get("attachments", [])
    if attachment_index < 0 or attachment_index >= len(attachments):
        raise HTTPException(404, "Pièce jointe introuvable")
    item = attachments[attachment_index]
    with db() as conn:
        stored = conn.execute(
            "SELECT * FROM evidence_attachments WHERE analysis_id=? AND position=?",
            (analysis_id, attachment_index),
        ).fetchone()
        if stored:
            try:
                data = storage().read(stored["storage_key"], stored["sha256"])
            except (FileNotFoundError, ValueError) as exc:
                raise HTTPException(
                    409, "Preuve indisponible ou intégrité non vérifiée"
                ) from exc
        else:
            row = conn.execute(
                "SELECT result FROM analyses WHERE id=?", (analysis_id,)
            ).fetchone()
            data = base64.b64decode(
                json.loads(row["result"])["eml"]["attachments"][attachment_index][
                    "raw"
                ],
                validate=True,
            )
    name = (
        (item.get("filename") or f"attachment-{attachment_index + 1}")
        .replace(chr(92), "/")
        .rsplit("/", 1)[-1]
    )
    name = "".join(c for c in name if c.isprintable())[:180] or "attachment"
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f"attachment; filename=attachment-{attachment_index + 1}.bin; filename*=UTF-8''{quote(name, safe='')}",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
            "Cache-Control": "no-store",
        },
    )


class Preferences(BaseModel):
    locale: Literal["fr", "en"]


@router.get("/auth/preferences")
def preferences(user: User):
    with db() as conn:
        return {
            "locale": conn.execute(
                "SELECT locale FROM users WHERE id=?", (user["id"],)
            ).fetchone()["locale"]
        }


@router.put("/auth/preferences")
def save_preferences(data: Preferences, user: User):
    with db() as conn:
        conn.execute("UPDATE users SET locale=? WHERE id=?", (data.locale, user["id"]))
    return data
