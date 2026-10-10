"""Operational follow-up: versioned actions, reporter replies and sourced intelligence.

Evidence is never altered. A reply requires an explicit send and a configured
transport; provider acceptance does not mean recipient delivery.
"""

import json
import os
import smtplib
import ssl
from contextvars import ContextVar
from datetime import date
from email.message import EmailMessage
from typing import Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, Field, field_validator

from .auth import User, Writer
from .investigations import _exists, _page
from .store import audit, db

router = APIRouter()
reply_transport_factory: ContextVar = ContextVar(
    "phishcase_reply_transport", default=None
)


def initialize_workflows(conn):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(cases)")}
    if "revision" not in columns:
        conn.execute("ALTER TABLE cases ADD COLUMN revision INTEGER NOT NULL DEFAULT 1")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS case_actions (
          id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id),
          title TEXT NOT NULL, owner_id INTEGER REFERENCES users(id), due_date TEXT,
          status TEXT NOT NULL DEFAULT 'todo', proof TEXT NOT NULL DEFAULT '',
          revision INTEGER NOT NULL DEFAULT 1, created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX IF NOT EXISTS actions_case ON case_actions(case_id,status,due_date);
        CREATE TABLE IF NOT EXISTS reporter_replies (
          id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id),
          analysis_id TEXT REFERENCES analyses(id), recipient TEXT NOT NULL, subject TEXT NOT NULL,
          body TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft', revision INTEGER NOT NULL DEFAULT 1,
          created_by INTEGER NOT NULL REFERENCES users(id), sent_by INTEGER REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          accepted_at TEXT, transport_error TEXT);
        CREATE INDEX IF NOT EXISTS replies_case ON reporter_replies(case_id,id DESC);
        CREATE TABLE IF NOT EXISTS intelligence_links (
          id INTEGER PRIMARY KEY, case_id INTEGER REFERENCES cases(id), campaign_id INTEGER REFERENCES campaigns(id),
          title TEXT NOT NULL, source TEXT NOT NULL, facts TEXT NOT NULL, counter_evidence TEXT NOT NULL DEFAULT '',
          hypothesis TEXT NOT NULL DEFAULT '', confidence INTEGER NOT NULL DEFAULT 0,
          observed_at TEXT NOT NULL, revision INTEGER NOT NULL DEFAULT 1,
          created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX IF NOT EXISTS intelligence_case ON intelligence_links(case_id,id DESC);
    """)
    reply_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(reporter_replies)")
    }
    for name, definition in (
        ("reconciliation_proof", "TEXT NOT NULL DEFAULT ''"),
        ("resolved_by", "INTEGER REFERENCES users(id)"),
        ("resolved_at", "TEXT"),
    ):
        if name not in reply_columns:
            conn.execute(f"ALTER TABLE reporter_replies ADD COLUMN {name} {definition}")


def conflict():
    raise HTTPException(
        409,
        "Un autre analyste a modifié cet élément. Rechargez sa version avant d’enregistrer vos changements.",  # noqa: RUF001
    )


def validate_owner(conn, user_id):
    if (
        user_id is not None
        and not conn.execute(
            "SELECT id FROM users WHERE id=? AND active=1 AND role IN ('admin','analyst')",
            (user_id,),
        ).fetchone()
    ):
        raise HTTPException(422, "Responsable invalide")


def guard_closure(conn, case_id):
    pending = conn.execute(
        "SELECT count(*) FROM case_actions WHERE case_id=? AND status IN ('todo','doing')",
        (case_id,),
    ).fetchone()[0]
    undecided = conn.execute(
        """SELECT count(*) FROM analyses a WHERE a.case_id=? AND
        (a.status IN ('queued','running') OR (a.status='completed' AND
         COALESCE((SELECT d.action FROM analyst_decisions d WHERE d.analysis_id=a.id ORDER BY d.id DESC LIMIT 1),'reopened')='reopened'))""",
        (case_id,),
    ).fetchone()[0]
    sending = conn.execute(
        "SELECT count(*) FROM reporter_replies WHERE case_id=? AND status='sending'",
        (case_id,),
    ).fetchone()[0]
    if pending or undecided or sending:
        raise HTTPException(
            409,
            "Clôture impossible : terminez les actions, qualifiez les messages et vérifiez les réponses en cours.",
        )


def workflow_scope(conn, case_id=None, campaign_id=None, analysis_id=None):
    if campaign_id is not None:
        from .collections import campaign

        context = campaign(conn, campaign_id)
        if (
            analysis_id is not None
            and not conn.execute(
                "SELECT analysis_id FROM campaign_analyses WHERE campaign_id=? AND analysis_id=?",
                (campaign_id, analysis_id),
            ).fetchone()
        ):
            raise HTTPException(422, "Le mail doit appartenir à cette campagne")
        return context
    if analysis_id is not None:
        _exists(conn, "analyses", analysis_id, "Analyse introuvable")
        return {"status": "active"}
    if case_id is not None:
        return _exists(conn, "cases", case_id, "Dossier introuvable")
    raise HTTPException(422, "Un mail ou une campagne est requis")


class ActionInput(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    owner_id: int | None = None
    due_date: date | None = None
    status: Literal["todo", "doing", "done", "cancelled"] = "todo"
    proof: str = Field(default="", max_length=20000)
    revision: int | None = Field(default=None, ge=1)

    @field_validator("title")
    @classmethod
    def title_nonblank(cls, value):
        if not value.strip():
            raise ValueError("Titre requis")
        return value.strip()


ACTION_SELECT = """SELECT a.*,u.username AS owner FROM case_actions a LEFT JOIN users u ON u.id=a.owner_id"""


@router.get("/actions")
def all_actions(
    user: User, scope: Literal["team", "mine"] = "team", status: str = "", page: int = 1
):
    with db() as conn:
        return _page(
            conn,
            ACTION_SELECT
            + " LEFT JOIN cases c ON c.id=a.case_id WHERE (?='team' OR a.owner_id=?) AND (?='' OR a.status=?) ORDER BY a.updated_at DESC,a.id DESC",
            (scope, user["id"], status, status),
            max(1, page),
            50,
        )


@router.get("/cases/{case_id}/actions")
def actions(case_id: int, user: User):
    with db() as conn:
        _exists(conn, "cases", case_id, "Dossier introuvable")
        return [
            dict(row)
            for row in conn.execute(
                ACTION_SELECT + " WHERE a.case_id=? ORDER BY a.id DESC", (case_id,)
            )
        ]


@router.post("/cases/{case_id}/actions", status_code=201)
def create_action(
    case_id: int | None,
    data: ActionInput,
    user: Writer,
    campaign_id: int | None = None,
    analysis_id: str | None = None,
):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        context = workflow_scope(conn, case_id, campaign_id, analysis_id)
        if context["status"] == "closed":
            raise HTTPException(409, "Rouvrez la campagne avant de créer une action")
        validate_owner(conn, data.owner_id)
        if data.status in {"done", "cancelled"} and not data.proof.strip():
            raise HTTPException(
                422,
                "Documentez le résultat ou le motif de l’annulation",  # noqa: RUF001
            )
        cursor = conn.execute(
            "INSERT INTO case_actions(case_id,title,owner_id,due_date,status,proof,created_by,campaign_id,analysis_id) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                case_id,
                data.title,
                data.owner_id,
                data.due_date.isoformat() if data.due_date else None,
                data.status,
                data.proof,
                user["id"],
                campaign_id,
                analysis_id,
            ),
        )
        audit(conn, user["id"], "action.created", case_id, str(cursor.lastrowid))
        return dict(
            conn.execute(
                ACTION_SELECT + " WHERE a.id=?", (cursor.lastrowid,)
            ).fetchone()
        )


@router.put("/actions/{action_id}")
def update_action(action_id: int, data: ActionInput, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM case_actions WHERE id=?", (action_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Action introuvable")
        if data.revision != row["revision"]:
            conflict()
        context = workflow_scope(
            conn, row["case_id"], row["campaign_id"], row["analysis_id"]
        )
        if context["status"] == "closed":
            raise HTTPException(409, "Rouvrez la campagne avant de modifier une action")
        validate_owner(conn, data.owner_id)
        if data.status in {"done", "cancelled"} and not data.proof.strip():
            raise HTTPException(
                422,
                "Documentez le résultat ou le motif de l’annulation",  # noqa: RUF001
            )
        conn.execute(
            "UPDATE case_actions SET title=?,owner_id=?,due_date=?,status=?,proof=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (
                data.title,
                data.owner_id,
                data.due_date.isoformat() if data.due_date else None,
                data.status,
                data.proof,
                action_id,
            ),
        )
        audit(
            conn,
            user["id"],
            "action.updated",
            row["case_id"],
            json.dumps({"action_id": action_id, "data": data.model_dump(mode="json")}),
        )
        return dict(
            conn.execute(ACTION_SELECT + " WHERE a.id=?", (action_id,)).fetchone()
        )


class ReplyInput(BaseModel):
    recipient: EmailStr
    subject: str = Field(min_length=1, max_length=240)
    body: str = Field(min_length=1, max_length=20000)
    analysis_id: str | None = None
    revision: int | None = Field(default=None, ge=1)

    @field_validator("subject")
    @classmethod
    def safe_subject(cls, value):
        if "\r" in value or "\n" in value or not value.strip():
            raise ValueError("Objet invalide")
        return value.strip()


class VersionInput(BaseModel):
    revision: int = Field(ge=1)


def smtp_send(recipient, subject, body):
    message = EmailMessage()
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(body)
    implicit = os.environ.get("SMTP_SSL", "false") == "true"
    transport = smtplib.SMTP_SSL if implicit else smtplib.SMTP
    options = {"context": ssl.create_default_context()} if implicit else {}
    with transport(
        os.environ["SMTP_HOST"],
        int(os.environ.get("SMTP_PORT", "465" if implicit else "587")),
        timeout=15,
        **options,
    ) as client:
        if not implicit:
            client.starttls(context=ssl.create_default_context())
        if os.environ.get("SMTP_USERNAME"):
            client.login(os.environ["SMTP_USERNAME"], os.environ["SMTP_PASSWORD"])
        client.send_message(message)


def reply_transport():
    factory = reply_transport_factory.get()
    if factory is not None:
        return factory()
    return (
        smtp_send
        if os.environ.get("SMTP_HOST") and os.environ.get("SMTP_FROM")
        else None
    )


@router.get("/cases/{case_id}/replies")
def replies(case_id: int, user: User):
    with db() as conn:
        _exists(conn, "cases", case_id, "Dossier introuvable")
        return {
            "transport_configured": reply_transport() is not None,
            "items": [
                dict(row)
                for row in conn.execute(
                    "SELECT * FROM reporter_replies WHERE case_id=? ORDER BY id DESC",
                    (case_id,),
                )
            ],
        }


@router.post("/cases/{case_id}/replies", status_code=201)
def create_reply(
    case_id: int | None, data: ReplyInput, user: Writer, campaign_id: int | None = None
):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        workflow_scope(conn, case_id, campaign_id, data.analysis_id)
        if data.analysis_id:
            analysis = _exists(
                conn, "analyses", data.analysis_id, "Analyse introuvable"
            )
            if case_id is not None and analysis["case_id"] != case_id:
                raise HTTPException(422, "Le message doit appartenir à ce dossier")
        cursor = conn.execute(
            "INSERT INTO reporter_replies(case_id,analysis_id,recipient,subject,body,created_by,campaign_id) VALUES (?,?,?,?,?,?,?)",
            (
                case_id,
                data.analysis_id,
                str(data.recipient),
                data.subject,
                data.body,
                user["id"],
                campaign_id,
            ),
        )
        audit(conn, user["id"], "reply.drafted", case_id, str(cursor.lastrowid))
        return dict(
            conn.execute(
                "SELECT * FROM reporter_replies WHERE id=?", (cursor.lastrowid,)
            ).fetchone()
        )


@router.put("/replies/{reply_id}")
def update_reply(reply_id: int, data: ReplyInput, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM reporter_replies WHERE id=?", (reply_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Réponse introuvable")
        if data.revision != row["revision"]:
            conflict()
        if row["status"] not in {"draft", "failed"}:
            raise HTTPException(
                409, "Cette réponse a déjà été transmise ou son envoi reste à vérifier"
            )
        workflow_scope(conn, row["case_id"], row["campaign_id"], data.analysis_id)
        if row["analysis_id"] and data.analysis_id != row["analysis_id"]:
            raise HTTPException(422, "Le mail de cette réponse ne peut pas être changé")
        if data.analysis_id:
            analysis = _exists(
                conn, "analyses", data.analysis_id, "Analyse introuvable"
            )
            if row["case_id"] is not None and analysis["case_id"] != row["case_id"]:
                raise HTTPException(422, "Le message doit appartenir à ce dossier")
        conn.execute(
            "UPDATE reporter_replies SET recipient=?,subject=?,body=?,analysis_id=?,status='draft',reconciliation_proof='',resolved_by=NULL,resolved_at=NULL,transport_error=NULL,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (str(data.recipient), data.subject, data.body, data.analysis_id, reply_id),
        )
        audit(conn, user["id"], "reply.updated", row["case_id"], str(reply_id))
        return dict(
            conn.execute(
                "SELECT * FROM reporter_replies WHERE id=?", (reply_id,)
            ).fetchone()
        )


@router.get("/replies/{reply_id}/preview")
def preview_reply(reply_id: int, user: User):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM reporter_replies WHERE id=?", (reply_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Réponse introuvable")
        return {
            key: row[key]
            for key in ("recipient", "subject", "body", "status", "revision")
        }


@router.post("/replies/{reply_id}/send")
def send_reply(reply_id: int, data: VersionInput, user: Writer):
    transport = reply_transport()
    if transport is None:
        raise HTTPException(
            409, "Aucun transport de réponse configuré. Le brouillon reste disponible."
        )
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM reporter_replies WHERE id=?", (reply_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Réponse introuvable")
        if row["revision"] != data.revision:
            conflict()
        if row["status"] != "draft":
            raise HTTPException(
                409,
                "Seul un brouillon peut être envoyé ; un envoi en cours ne doit pas être répété",
            )
        if (
            row["analysis_id"]
            and not conn.execute(
                "SELECT id FROM analyst_decisions WHERE analysis_id=? AND action='decided' AND id=(SELECT max(id) FROM analyst_decisions WHERE analysis_id=?)",
                (row["analysis_id"], row["analysis_id"]),
            ).fetchone()
        ):
            raise HTTPException(
                409, "Enregistrez une décision analyste avant de répondre au signalant"
            )
        conn.execute(
            "UPDATE reporter_replies SET status='sending',sent_by=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (user["id"], reply_id),
        )
        audit(conn, user["id"], "reply.send_requested", row["case_id"], str(reply_id))
    # Never hold a database transaction across a remote transport call. A crash
    # leaves 'sending' visible for manual reconciliation, never an automatic retry.
    try:
        transport(row["recipient"], row["subject"], row["body"])
        state, failure = "accepted", None
    except Exception:
        state, failure = (
            "uncertain",
            "La transmission n’a pas pu être confirmée. Vérifiez le transport avant tout nouvel envoi.",  # noqa: RUF001
        )
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        result = conn.execute(
            "UPDATE reporter_replies SET status=?,transport_error=?,accepted_at=CASE WHEN ?='accepted' THEN CURRENT_TIMESTAMP ELSE NULL END,updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='sending' AND revision=?",
            (state, failure, state, reply_id, row["revision"] + 1),
        )
        audit(
            conn,
            user["id"],
            "reply." + state if result.rowcount else "reply.transport_observed",
            row["case_id"],
            json.dumps({"reply_id": reply_id, "transport_result": state}),
        )
        return dict(
            conn.execute(
                "SELECT * FROM reporter_replies WHERE id=?", (reply_id,)
            ).fetchone()
        )


class ReconciliationInput(BaseModel):
    revision: int = Field(ge=1)
    outcome: Literal["accepted", "failed"]
    proof: str = Field(min_length=1, max_length=20000)

    @field_validator("proof")
    @classmethod
    def proof_required(cls, value):
        if not value.strip():
            raise ValueError("Preuve de rapprochement requise")
        return value.strip()


@router.post("/replies/{reply_id}/reconcile")
def reconcile_reply(reply_id: int, data: ReconciliationInput, user: Writer):
    """Record an analyst's verified transport result; never initiate a transmission."""
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM reporter_replies WHERE id=?", (reply_id,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Réponse introuvable")
        if row["revision"] != data.revision:
            conflict()
        if row["status"] not in {"sending", "uncertain"}:
            raise HTTPException(
                409, "Seule une transmission à vérifier peut être rapprochée"
            )
        conn.execute(
            """UPDATE reporter_replies SET status=?,reconciliation_proof=?,resolved_by=?,resolved_at=CURRENT_TIMESTAMP,
            transport_error=NULL,accepted_at=CASE WHEN ?='accepted' THEN CURRENT_TIMESTAMP ELSE NULL END,
            revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (data.outcome, data.proof, user["id"], data.outcome, reply_id),
        )
        audit(
            conn,
            user["id"],
            "reply.reconciled",
            row["case_id"],
            json.dumps({"reply_id": reply_id, "result": data.model_dump()}),
        )
        return dict(
            conn.execute(
                "SELECT * FROM reporter_replies WHERE id=?", (reply_id,)
            ).fetchone()
        )


class IntelligenceInput(BaseModel):
    case_id: int | None = None
    campaign_id: int | None = None
    title: str = Field(min_length=1, max_length=240)
    source: str = Field(min_length=1, max_length=2000)
    facts: str = Field(min_length=1, max_length=20000)
    counter_evidence: str = Field(default="", max_length=20000)
    hypothesis: str = Field(default="", max_length=20000)
    confidence: int = Field(default=0, ge=0, le=100)
    observed_at: date
    revision: int | None = Field(default=None, ge=1)

    @field_validator("title", "source", "facts")
    @classmethod
    def required_text(cls, value):
        if not value.strip():
            raise ValueError("Champ requis")
        return value.strip()


@router.get("/intelligence")
def intelligence(
    user: User,
    case_id: int | None = None,
    campaign_id: int | None = None,
    page: int = 1,
):
    with db() as conn:
        return _page(
            conn,
            """SELECT i.*,u.username,c.title AS case_title,p.name AS campaign_name FROM intelligence_links i
            JOIN users u ON u.id=i.created_by LEFT JOIN cases c ON c.id=i.case_id LEFT JOIN campaigns p ON p.id=i.campaign_id
            WHERE (? IS NULL OR i.case_id=?) AND (? IS NULL OR i.campaign_id=?) ORDER BY i.id DESC""",
            (case_id, case_id, campaign_id, campaign_id),
            max(1, page),
            50,
        )


def save_intelligence(data, user, identity=None):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if data.case_id is not None:
            _exists(conn, "cases", data.case_id, "Dossier introuvable")
        if data.campaign_id is not None:
            _exists(conn, "campaigns", data.campaign_id, "Campagne introuvable")
        values = (
            data.case_id,
            data.campaign_id,
            data.title,
            data.source,
            data.facts,
            data.counter_evidence,
            data.hypothesis,
            data.confidence,
            data.observed_at.isoformat(),
        )
        if identity is None:
            cursor = conn.execute(
                "INSERT INTO intelligence_links(case_id,campaign_id,title,source,facts,counter_evidence,hypothesis,confidence,observed_at,created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (*values, user["id"]),
            )
            identity = cursor.lastrowid
        else:
            row = conn.execute(
                "SELECT * FROM intelligence_links WHERE id=?", (identity,)
            ).fetchone()
            if not row:
                raise HTTPException(404, "Observation introuvable")
            if row["revision"] != data.revision:
                conflict()
            conn.execute(
                "UPDATE intelligence_links SET case_id=?,campaign_id=?,title=?,source=?,facts=?,counter_evidence=?,hypothesis=?,confidence=?,observed_at=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (*values, identity),
            )
        audit(conn, user["id"], "intelligence.documented", data.case_id, str(identity))
        if data.campaign_id is not None:
            conn.execute(
                "INSERT INTO campaign_events(campaign_id,event_id) VALUES (?,last_insert_rowid())",
                (data.campaign_id,),
            )
        return dict(
            conn.execute(
                "SELECT * FROM intelligence_links WHERE id=?", (identity,)
            ).fetchone()
        )


@router.post("/intelligence", status_code=201)
def create_intelligence(data: IntelligenceInput, user: Writer):
    return save_intelligence(data, user)


@router.put("/intelligence/{identity}")
def update_intelligence(identity: int, data: IntelligenceInput, user: Writer):
    return save_intelligence(data, user, identity)
