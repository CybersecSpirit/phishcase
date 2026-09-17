import asyncio
import hashlib
import json
import secrets
import sqlite3
import time
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response, UploadFile
from pydantic import BaseModel, Field

from backend import dependencies
from backend.api.endpoints.analyze import _analyze

from .auth import Admin, User, Writer, secure_cookie
from .store import audit, db, password_hash, password_matches

router = APIRouter()


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
    if request.headers.get("x-requested-with") != "EML-Investigation":
        raise HTTPException(403, "En-tête de protection CSRF requis")
    identity = data.username.lower()
    with db() as conn:
        # Serialize attempts; persistent throttling also works across API workers.
        conn.execute("BEGIN IMMEDIATE")
        attempt = conn.execute(
            "SELECT * FROM login_attempts WHERE identity=?", (identity,)
        ).fetchone()
        now = time.time()
        if attempt and now - attempt["window"] < 900 and attempt["count"] >= 10:
            raise HTTPException(429, "Trop de tentatives. Réessayer dans 15 minutes.")
        if not attempt or now - attempt["window"] >= 900:
            conn.execute(
                "INSERT OR REPLACE INTO login_attempts VALUES (?,1,?)", (identity, now)
            )
        else:
            conn.execute(
                "UPDATE login_attempts SET count=count+1 WHERE identity=?", (identity,)
            )
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
        token = secrets.token_urlsafe(32)
        conn.execute("DELETE FROM sessions WHERE expires<=?", (now,))
        conn.execute(
            "INSERT INTO sessions VALUES (?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), user["id"], now + 28800),
        )
        conn.execute("DELETE FROM login_attempts WHERE identity=?", (identity,))
        audit(conn, user["id"], "login")
    response.set_cookie(
        "eml_session",
        token,
        httponly=True,
        secure=secure_cookie(),
        samesite="strict",
        max_age=28800,
    )
    return {"id": user["id"], "username": user["username"], "role": user["role"]}


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
                "SELECT id,username,role,active,created_at FROM users ORDER BY username"
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
        conn.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))
        audit(conn, user["id"], "user.updated", detail=target["username"])
    return {"ok": True}


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


@router.get("/cases")
def cases(user: User, q: str = "", status: str = ""):
    with db() as conn:
        return [
            dict(r)
            for r in conn.execute(
                """SELECT c.*,u.username AS assignee,
            (SELECT count(*) FROM analyses a WHERE a.case_id=c.id) AS analysis_count
            FROM cases c LEFT JOIN users u ON u.id=c.assignee_id
            WHERE (c.title LIKE ? OR c.description LIKE ?) AND (?='' OR c.status=?)
            ORDER BY c.updated_at DESC,c.id DESC LIMIT 500""",
                (f"%{q}%", f"%{q}%", status, status),
            )
        ]


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


@router.get("/analyses")
def analyses(user: User, case_id: int | None = None):
    with db() as conn:
        return [
            dict(r)
            for r in conn.execute(
                "SELECT id,case_id,filename,sha256,status,subject,error,created_at,finished_at FROM analyses WHERE (? IS NULL OR case_id=?) ORDER BY created_at DESC LIMIT 500",
                (case_id, case_id),
            )
        ]


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
        result["result"] = json.loads(result["result"]) if result["result"] else None
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


@router.post("/cases/{case_id}/analyses", status_code=201)
async def upload(
    case_id: int,
    file: UploadFile,
    user: Writer,
    spam_assassin: dependencies.SpamAssassin,
    optional_email_rep: dependencies.OptionalEmailRep,
    optional_vt: dependencies.OptionalVirusTotal,
    optional_urlscan: dependencies.OptionalUrlScan,
):
    with db() as conn:
        case_exists(conn, case_id)
    raw = await file.read(20 * 1024 * 1024 + 1)
    if len(raw) > 20 * 1024 * 1024:
        raise HTTPException(413, "Fichier limité à 20 Mo")
    if not raw:
        raise HTTPException(422, "Fichier vide")
    analysis_id = str(uuid4())
    with db() as conn:
        conn.execute(
            "INSERT INTO analyses(id,case_id,filename,sha256,status,created_by,source) VALUES (?,?,?,?,'running',?,?)",
            (
                analysis_id,
                case_id,
                (file.filename or "message.eml")[:255],
                hashlib.sha256(raw).hexdigest(),
                user["id"],
                raw,
            ),
        )
        audit(conn, user["id"], "analysis.started", case_id, analysis_id)
    try:
        result = await asyncio.wait_for(
            _analyze(
                raw,
                spam_assassin=spam_assassin,
                optional_email_rep=optional_email_rep,
                optional_vt=optional_vt,
                optional_urlscan=optional_urlscan,
            ),
            timeout=180,
        )
        document = result.model_dump(mode="json", by_alias=False)
        with db() as conn:
            conn.execute(
                "UPDATE analyses SET status='completed',subject=?,result=?,finished_at=CURRENT_TIMESTAMP WHERE id=?",
                (
                    document["eml"]["header"]["subject"],
                    json.dumps(document),
                    analysis_id,
                ),
            )
            for kind, value in extract_iocs(document):
                conn.execute(
                    "INSERT OR IGNORE INTO iocs(kind,value) VALUES (?,?)", (kind, value)
                )
                conn.execute(
                    "INSERT OR IGNORE INTO analysis_iocs SELECT ?,id FROM iocs WHERE kind=? AND value=?",
                    (analysis_id, kind, value),
                )
            audit(conn, user["id"], "analysis.completed", case_id, analysis_id)
    except (Exception, asyncio.CancelledError) as exc:
        with db() as conn:
            conn.execute(
                "UPDATE analyses SET status='failed',error=?,finished_at=CURRENT_TIMESTAMP WHERE id=?",
                (
                    "Analyse interrompue ou impossible ; vérifier le format et les services configurés.",
                    analysis_id,
                ),
            )
            audit(conn, user["id"], "analysis.failed", case_id, analysis_id)
        if isinstance(exc, asyncio.CancelledError):
            raise
    return get_analysis(analysis_id, user)


@router.get("/iocs")
def iocs(user: User, q: str = "", case_id: int | None = None):
    with db() as conn:
        return [
            dict(r)
            for r in conn.execute(
                """SELECT i.*,count(DISTINCT ai.analysis_id) AS analysis_count,
            count(DISTINCT a.case_id) AS case_count FROM iocs i
            JOIN analysis_iocs ai ON ai.ioc_id=i.id JOIN analyses a ON a.id=ai.analysis_id
            WHERE i.value LIKE ? AND (? IS NULL OR a.case_id=?) GROUP BY i.id ORDER BY i.id DESC LIMIT 1000""",
                (f"%{q}%", case_id, case_id),
            )
        ]


@router.get("/iocs/{ioc_id}/occurrences")
def occurrences(ioc_id: int, user: User):
    with db() as conn:
        return [
            dict(r)
            for r in conn.execute(
                """SELECT a.id,a.filename,a.case_id,c.title FROM analyses a
            JOIN analysis_iocs ai ON ai.analysis_id=a.id JOIN cases c ON c.id=a.case_id WHERE ai.ioc_id=?""",
                (ioc_id,),
            )
        ]


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
    with db() as conn:
        row = conn.execute(
            "SELECT source,filename FROM analyses WHERE id=?", (analysis_id,)
        ).fetchone()
        if not row or row["source"] is None:
            raise HTTPException(404, "Source indisponible")
        suffix = ".msg" if row["filename"].lower().endswith(".msg") else ".eml"
        return Response(
            content=row["source"],
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{analysis_id}{suffix}"',
                "X-Content-Type-Options": "nosniff",
            },
        )
