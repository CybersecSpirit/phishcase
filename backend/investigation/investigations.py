"""Local investigation workflows; human decisions never mutate analysis evidence."""

import hashlib
import json
import re
from email.utils import getaddresses
from math import ceil
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from .auth import User, Writer
from .store import audit, db

router = APIRouter()
VerdictValue = Literal[
    "legitimate",
    "spam",
    "phishing",
    "credential_phishing",
    "malware_delivery",
    "bec_fraud",
    "suspicious",
    "inconclusive",
]


def initialize_investigations(conn):
    """Idempotent additive migration, including existing analysis search indexes."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS analyst_decisions (
          id INTEGER PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id),
          action TEXT NOT NULL CHECK(action IN ('decided','reopened')),
          verdict TEXT, confidence INTEGER, justification TEXT NOT NULL,
          actor_id INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX IF NOT EXISTS decisions_analysis ON analyst_decisions(analysis_id,id DESC);
        CREATE TABLE IF NOT EXISTS campaigns (
          id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
          tags TEXT NOT NULL DEFAULT '[]', status TEXT NOT NULL DEFAULT 'active', verdict TEXT,
          created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, deleted_at TEXT);
        CREATE TABLE IF NOT EXISTS campaign_cases (
          campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
          case_id INTEGER NOT NULL REFERENCES cases(id),
          PRIMARY KEY(campaign_id,case_id));
        CREATE INDEX IF NOT EXISTS campaign_cases_case ON campaign_cases(case_id,campaign_id);
        CREATE TABLE IF NOT EXISTS campaign_events (
          campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
          event_id INTEGER NOT NULL REFERENCES events(id), PRIMARY KEY(campaign_id,event_id));
        CREATE TABLE IF NOT EXISTS analysis_signals (
          analysis_id TEXT NOT NULL REFERENCES analyses(id), kind TEXT NOT NULL, value TEXT NOT NULL,
          PRIMARY KEY(analysis_id,kind,value));
        CREATE INDEX IF NOT EXISTS signals_value ON analysis_signals(kind,value,analysis_id);
        CREATE TABLE IF NOT EXISTS analysis_indexed (
          analysis_id TEXT PRIMARY KEY REFERENCES analyses(id));
        CREATE INDEX IF NOT EXISTS analyses_created ON analyses(created_at DESC,id DESC);
        CREATE INDEX IF NOT EXISTS analysis_iocs_ioc ON analysis_iocs(ioc_id,analysis_id);
    """)
    # Fetch metadata one row at a time; never load original binary evidence.
    rows = conn.execute("""SELECT a.id,a.result FROM analyses a
        LEFT JOIN analysis_indexed x ON x.analysis_id=a.id
        WHERE a.status='completed' AND x.analysis_id IS NULL""")
    for row in rows:
        try:
            document = json.loads(row["result"] or "{}")
        except ValueError, TypeError:
            document = {}
        index_analysis(conn, row["id"], document if isinstance(document, dict) else {})


def _header_values(values):
    return [values] if isinstance(values, str) else values or []


def _address_signals(header, raw_headers, add):
    for kind, values in (
        (
            "sender",
            header.get("from_") or header.get("from") or raw_headers.get("from", []),
        ),
        ("reply_to", raw_headers.get("reply-to", [])),
    ):
        for _, address in getaddresses(
            [str(value) for value in _header_values(values)]
        ):
            add(kind, address.casefold())
            if "@" in address:
                add(
                    "sender_domain" if kind == "sender" else "reply_to_domain",
                    address.rsplit("@", 1)[1].casefold(),
                )


def index_analysis(conn, analysis_id, document):
    """Index exact, explainable signals after a result is persisted by the worker."""
    eml = document.get("eml") or {}
    header = eml.get("header") or {}
    raw_headers = {
        key.lower(): value for key, value in (header.get("header") or {}).items()
    }
    signals = set()

    def add(kind, value):
        if isinstance(value, str) and value.strip():
            signals.add((kind, value.strip()))

    subject = " ".join((header.get("subject") or "").casefold().split())
    subject = re.sub(r"^(?:(?:re|fw|fwd)\s*:\s*)+", "", subject)
    add("subject", subject)
    _address_signals(header, raw_headers, add)
    add("message_id", header.get("message_id"))
    for value in _header_values(raw_headers.get("message-id", [])):
        add("message_id", value)
    for attachment in eml.get("attachments") or []:
        add("attachment_name", attachment.get("filename"))
        add("sha256", (attachment.get("hash") or {}).get("sha256"))
    for body in eml.get("bodies") or []:
        content = " ".join((body.get("content") or "").split())
        # Tiny signatures/disclaimers do not constitute a meaningful shared body.
        if len(content) >= 80:
            add("body_sha256", hashlib.sha256(content.encode()).hexdigest())
    row = conn.execute(
        "SELECT sha256 FROM analyses WHERE id=?", (analysis_id,)
    ).fetchone()
    if row:
        add("original_sha256", row["sha256"])
    conn.execute("DELETE FROM analysis_signals WHERE analysis_id=?", (analysis_id,))
    conn.executemany(
        "INSERT INTO analysis_signals VALUES (?,?,?)",
        [(analysis_id, kind, value) for kind, value in signals],
    )
    conn.execute("INSERT OR IGNORE INTO analysis_indexed VALUES (?)", (analysis_id,))


def _exists(conn, table, identity, label):
    # table is an internal constant, never caller-controlled.
    fields = "id,case_id,status" if table == "analyses" else "*"
    row = conn.execute(
        f"SELECT {fields} FROM {table} WHERE id=?", (identity,)
    ).fetchone()
    if row is None or (table == "campaigns" and row["deleted_at"]):
        raise HTTPException(404, label)
    return dict(row)


def _pattern(value):
    """Literal substring search: '%' and '_' supplied by users are not wildcards."""
    return (
        "%" + value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    )


def _page(conn, sql, params=(), page=1, page_size=50, transform=None):
    if not conn.in_transaction:
        conn.execute("BEGIN")  # Count and rows share the same read snapshot.
    total = conn.execute(f"SELECT count(*) FROM ({sql})", params).fetchone()[0]
    rows = [
        dict(row)
        for row in conn.execute(
            sql + " LIMIT ? OFFSET ?", (*params, page_size, (page - 1) * page_size)
        )
    ]
    return {
        "items": [transform(row) for row in rows] if transform else rows,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": ceil(total / page_size),
    }


def _legacy_or_page(conn, sql, params, page, page_size, limit):
    if page is None and page_size is None and limit is None:
        # Keep small legacy arrays compatible without loading an unbounded result.
        # The extra row detects overflow; never return a silently truncated list.
        rows = [dict(row) for row in conn.execute(sql + " LIMIT ?", (*params, 501))]
        if len(rows) > 500:
            raise HTTPException(
                422,
                "Legacy lists are limited to 500 items; use pagination with page=1&page_size=50",
            )
        return rows
    return _page(conn, sql, params, page or 1, page_size or limit or 50)


CASE_SELECT = """SELECT c.*,u.username AS assignee,
    (SELECT count(*) FROM analyses a WHERE a.case_id=c.id) AS analysis_count
    FROM cases c LEFT JOIN users u ON u.id=c.assignee_id"""
ANALYSIS_SELECT = """SELECT a.id,a.case_id,a.filename,a.sha256,a.status,a.subject,a.error,
    a.created_at,a.finished_at,c.title AS case_title FROM analyses a JOIN cases c ON c.id=a.case_id"""
IOC_SELECT = """SELECT i.*,count(DISTINCT ai.analysis_id) AS analysis_count,
    count(DISTINCT a.case_id) AS case_count FROM iocs i
    JOIN analysis_iocs ai ON ai.ioc_id=i.id JOIN analyses a ON a.id=ai.analysis_id"""
CAMPAIGN_SELECT = """SELECT c.*,
    (SELECT count(*) FROM campaign_cases cc WHERE cc.campaign_id=c.id) AS case_count,
    (SELECT count(*) FROM analyses a JOIN campaign_cases cc ON cc.case_id=a.case_id WHERE cc.campaign_id=c.id) AS analysis_count
    FROM campaigns c"""


@router.get("/cases")
def cases(
    user: User,
    q: str = Query("", max_length=500),
    status: str = "",
    priority: str = "",
    assignee_id: int | None = None,
    page: int | None = Query(None, ge=1),
    page_size: int | None = Query(None, ge=1, le=200),
    limit: int | None = Query(None, ge=1, le=200),
):
    sql = (
        CASE_SELECT
        + """ WHERE (c.title LIKE ? ESCAPE '\\' OR c.description LIKE ? ESCAPE '\\')
        AND (?='' OR c.status=?) AND (?='' OR c.priority=?) AND (? IS NULL OR c.assignee_id=?)
        ORDER BY c.updated_at DESC,c.id DESC"""
    )
    with db() as conn:
        return _legacy_or_page(
            conn,
            sql,
            (
                _pattern(q),
                _pattern(q),
                status,
                status,
                priority,
                priority,
                assignee_id,
                assignee_id,
            ),
            page,
            page_size,
            limit,
        )


@router.get("/analyses")
def analyses(
    user: User,
    case_id: int | None = None,
    q: str = Query("", max_length=500),
    status: str = "",
    page: int | None = Query(None, ge=1),
    page_size: int | None = Query(None, ge=1, le=200),
    limit: int | None = Query(None, ge=1, le=200),
):
    sql = (
        ANALYSIS_SELECT
        + """ WHERE (? IS NULL OR a.case_id=?) AND (?='' OR a.status=?)
        AND (a.subject LIKE ? ESCAPE '\\' OR a.filename LIKE ? ESCAPE '\\' OR a.sha256 LIKE ? ESCAPE '\\'
          OR EXISTS(SELECT 1 FROM analysis_signals s WHERE s.analysis_id=a.id AND s.value LIKE ? ESCAPE '\\'))
        ORDER BY a.created_at DESC,a.id DESC"""
    )
    with db() as conn:
        if case_id is not None:
            _exists(conn, "cases", case_id, "Dossier introuvable")
        return _legacy_or_page(
            conn,
            sql,
            (case_id, case_id, status, status, *([_pattern(q)] * 4)),
            page,
            page_size,
            limit,
        )


@router.get("/cases/{case_id}/analyses")
def case_analyses(
    case_id: int,
    user: User,
    q: str = Query("", max_length=500),
    status: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    return analyses(user, case_id, q, status, page, page_size, None)


@router.get("/iocs")
def iocs(
    user: User,
    q: str = Query("", max_length=500),
    case_id: int | None = None,
    kind: str = "",
    verdict: str = "",
    page: int | None = Query(None, ge=1),
    page_size: int | None = Query(None, ge=1, le=200),
    limit: int | None = Query(None, ge=1, le=200),
):
    sql = (
        IOC_SELECT
        + """ WHERE i.value LIKE ? ESCAPE '\\' AND (? IS NULL OR a.case_id=?)
        AND (?='' OR i.kind=?) AND (?='' OR i.verdict=?) GROUP BY i.id ORDER BY i.id DESC"""
    )
    with db() as conn:
        if case_id is not None:
            _exists(conn, "cases", case_id, "Dossier introuvable")
        return _legacy_or_page(
            conn,
            sql,
            (_pattern(q), case_id, case_id, kind, kind, verdict, verdict),
            page,
            page_size,
            limit,
        )


@router.get("/iocs/{ioc_id}/occurrences")
def occurrences(
    ioc_id: int,
    user: User,
    q: str = Query("", max_length=500),
    case_id: int | None = None,
    status: str = "",
    page: int | None = Query(None, ge=1),
    page_size: int | None = Query(None, ge=1, le=200),
    limit: int | None = Query(None, ge=1, le=200),
):
    sql = """SELECT a.id,a.filename,a.subject,a.case_id,a.status,a.created_at,c.title FROM analyses a
        JOIN analysis_iocs ai ON ai.analysis_id=a.id JOIN cases c ON c.id=a.case_id
        WHERE ai.ioc_id=? AND (? IS NULL OR a.case_id=?) AND (?='' OR a.status=?)
        AND (a.subject LIKE ? ESCAPE '\\' OR a.filename LIKE ? ESCAPE '\\' OR c.title LIKE ? ESCAPE '\\')
        ORDER BY a.created_at DESC,a.id DESC"""
    with db() as conn:
        _exists(conn, "iocs", ioc_id, "IOC introuvable")
        return _legacy_or_page(
            conn,
            sql,
            (ioc_id, case_id, case_id, status, status, *([_pattern(q)] * 3)),
            page,
            page_size,
            limit,
        )


@router.get("/iocs/{ioc_id}")
def get_ioc(ioc_id: int, user: User):
    with db() as conn:
        result = _exists(conn, "iocs", ioc_id, "IOC introuvable")
        counts = conn.execute(
            IOC_SELECT + " WHERE i.id=? GROUP BY i.id", (ioc_id,)
        ).fetchone()
        result.update(
            dict(counts) if counts else {"analysis_count": 0, "case_count": 0}
        )
        result["campaigns"] = [
            dict(row)
            for row in conn.execute(
                """SELECT DISTINCT c.id,c.name FROM campaigns c
            JOIN campaign_cases cc ON cc.campaign_id=c.id JOIN analyses a ON a.case_id=cc.case_id
            JOIN analysis_iocs ai ON ai.analysis_id=a.id WHERE ai.ioc_id=? AND c.deleted_at IS NULL ORDER BY c.id DESC""",
                (ioc_id,),
            )
        ]
        return result


@router.get("/events")
def events(
    user: User,
    case_id: int | None = None,
    q: str = Query("", max_length=500),
    action: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with db() as conn:
        if case_id is not None:
            _exists(conn, "cases", case_id, "Dossier introuvable")
        return _page(
            conn,
            """SELECT e.*,u.username FROM events e LEFT JOIN users u ON u.id=e.actor_id
            WHERE (? IS NULL OR e.case_id=?) AND (?='' OR e.action=?)
            AND (e.action LIKE ? ESCAPE '\\' OR e.detail LIKE ? ESCAPE '\\' OR u.username LIKE ? ESCAPE '\\')
            ORDER BY e.id DESC""",
            (case_id, case_id, action, action, *([_pattern(q)] * 3)),
            page,
            page_size,
        )


@router.get("/cases/{case_id}/events")
def case_events(
    case_id: int,
    user: User,
    q: str = Query("", max_length=500),
    action: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    return events(user, case_id, q, action, page, page_size)


class Decision(BaseModel):
    verdict: VerdictValue
    confidence: int = Field(ge=0, le=100)
    justification: str = Field(min_length=1, max_length=20000)

    @field_validator("justification")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Une justification est requise")
        return value.strip()


class Reopen(BaseModel):
    justification: str = Field(min_length=1, max_length=20000)

    @field_validator("justification")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Une justification est requise")
        return value.strip()


DECISION_SELECT = """SELECT d.*,u.username FROM analyst_decisions d JOIN users u ON u.id=d.actor_id
    WHERE d.analysis_id=? ORDER BY d.id DESC"""


@router.get("/analyses/{analysis_id}/decision")
def get_decision(analysis_id: str, user: User):
    with db() as conn:
        _exists(conn, "analyses", analysis_id, "Analyse introuvable")
        history = _page(conn, DECISION_SELECT, (analysis_id,), 1, 50)
        latest = history["items"][0] if history["items"] else None
        return {
            "current": latest if latest and latest["action"] == "decided" else None,
            "history": history["items"],
            "history_total": history["total"],
        }


@router.get("/analyses/{analysis_id}/decision/history")
def decision_history(
    analysis_id: str,
    user: User,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with db() as conn:
        _exists(conn, "analyses", analysis_id, "Analyse introuvable")
        return _page(conn, DECISION_SELECT, (analysis_id,), page, page_size)


@router.put("/analyses/{analysis_id}/decision")
def decide(analysis_id: str, data: Decision, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        analysis = _exists(conn, "analyses", analysis_id, "Analyse introuvable")
        conn.execute(
            """INSERT INTO analyst_decisions(analysis_id,action,verdict,confidence,justification,actor_id)
            VALUES (?,'decided',?,?,?,?)""",
            (
                analysis_id,
                data.verdict,
                data.confidence,
                data.justification,
                user["id"],
            ),
        )
        audit(
            conn,
            user["id"],
            "analysis.decided",
            analysis["case_id"],
            json.dumps({"analysis_id": analysis_id, **data.model_dump()}),
        )
    return get_decision(analysis_id, user)


@router.post("/analyses/{analysis_id}/decision/reopen")
def reopen(analysis_id: str, data: Reopen, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        analysis = _exists(conn, "analyses", analysis_id, "Analyse introuvable")
        last = conn.execute(DECISION_SELECT, (analysis_id,)).fetchone()
        if last is None or last["action"] == "reopened":
            raise HTTPException(409, "Aucune décision à rouvrir")
        conn.execute(
            """INSERT INTO analyst_decisions(analysis_id,action,justification,actor_id)
            VALUES (?,'reopened',?,?)""",
            (analysis_id, data.justification, user["id"]),
        )
        conn.execute(
            "UPDATE cases SET status='investigating',updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (analysis["case_id"],),
        )
        audit(
            conn,
            user["id"],
            "analysis.reopened",
            analysis["case_id"],
            json.dumps(
                {"analysis_id": analysis_id, "justification": data.justification}
            ),
        )
    return get_decision(analysis_id, user)


class Campaign(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=20000)
    tags: list[str] = Field(default_factory=list, max_length=30)
    status: Literal["active", "closed"] = "active"
    verdict: VerdictValue | None = None

    @field_validator("name")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Un nom est requis")
        return value.strip()

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, values):
        cleaned = sorted(
            {value.strip().casefold() for value in values if value.strip()}
        )
        if any(len(value) > 80 for value in cleaned):
            raise ValueError("Chaque tag est limité à 80 caractères")
        return cleaned


def _campaign(row):
    row["tags"] = json.loads(row["tags"])
    return row


def _campaign_audit(conn, campaign_id, actor, action, detail="", case_id=None):
    audit(conn, actor, action, case_id, detail)
    conn.execute(
        "INSERT INTO campaign_events VALUES (?,last_insert_rowid())", (campaign_id,)
    )


@router.get("/campaigns")
def campaigns(
    user: User,
    q: str = Query("", max_length=500),
    status: str = "",
    tag: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with db() as conn:
        return _page(
            conn,
            CAMPAIGN_SELECT
            + """ WHERE c.deleted_at IS NULL AND (?='' OR c.status=?)
            AND (c.name LIKE ? ESCAPE '\\' OR c.description LIKE ? ESCAPE '\\' OR c.tags LIKE ? ESCAPE '\\')
            AND (?='' OR EXISTS(SELECT 1 FROM json_each(c.tags) t WHERE t.value=?))
            ORDER BY c.updated_at DESC,c.id DESC""",
            (status, status, *([_pattern(q)] * 3), tag, tag.casefold()),
            page,
            page_size,
            _campaign,
        )


@router.post("/campaigns", status_code=201)
def create_campaign(data: Campaign, user: Writer):
    with db() as conn:
        cursor = conn.execute(
            """INSERT INTO campaigns(name,description,tags,status,verdict,created_by)
            VALUES (?,?,?,?,?,?)""",
            (
                data.name,
                data.description,
                json.dumps(data.tags),
                data.status,
                data.verdict,
                user["id"],
            ),
        )
        campaign_id = cursor.lastrowid
        _campaign_audit(
            conn, campaign_id, user["id"], "campaign.created", data.model_dump_json()
        )
    return get_campaign(campaign_id, user)


@router.get("/campaigns/{campaign_id}")
def get_campaign(campaign_id: int, user: User):
    with db() as conn:
        _exists(conn, "campaigns", campaign_id, "Campagne introuvable")
        return _campaign(
            dict(
                conn.execute(
                    CAMPAIGN_SELECT + " WHERE c.id=?", (campaign_id,)
                ).fetchone()
            )
        )


@router.put("/campaigns/{campaign_id}")
def update_campaign(campaign_id: int, data: Campaign, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _exists(conn, "campaigns", campaign_id, "Campagne introuvable")
        conn.execute(
            """UPDATE campaigns SET name=?,description=?,tags=?,status=?,verdict=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
            (
                data.name,
                data.description,
                json.dumps(data.tags),
                data.status,
                data.verdict,
                campaign_id,
            ),
        )
        _campaign_audit(
            conn, campaign_id, user["id"], "campaign.updated", data.model_dump_json()
        )
    return get_campaign(campaign_id, user)


@router.delete("/campaigns/{campaign_id}")
def delete_campaign(campaign_id: int, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _exists(conn, "campaigns", campaign_id, "Campagne introuvable")
        # A tombstone retains links and audit history without deleting any case/evidence.
        conn.execute(
            "UPDATE campaigns SET deleted_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (campaign_id,),
        )
        _campaign_audit(
            conn, campaign_id, user["id"], "campaign.deleted", str(campaign_id)
        )
    return {"ok": True}


@router.put("/campaigns/{campaign_id}/cases/{case_id}")
def attach_case(campaign_id: int, case_id: int, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _exists(conn, "campaigns", campaign_id, "Campagne introuvable")
        _exists(conn, "cases", case_id, "Dossier introuvable")
        cursor = conn.execute(
            "INSERT OR IGNORE INTO campaign_cases VALUES (?,?)", (campaign_id, case_id)
        )
        if cursor.rowcount:
            conn.execute(
                "UPDATE campaigns SET updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (campaign_id,),
            )
            _campaign_audit(
                conn,
                campaign_id,
                user["id"],
                "campaign.case_attached",
                str(campaign_id),
                case_id,
            )
    return {"ok": True}


@router.delete("/campaigns/{campaign_id}/cases/{case_id}")
def detach_case(campaign_id: int, case_id: int, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        _exists(conn, "campaigns", campaign_id, "Campagne introuvable")
        _exists(conn, "cases", case_id, "Dossier introuvable")
        cursor = conn.execute(
            "DELETE FROM campaign_cases WHERE campaign_id=? AND case_id=?",
            (campaign_id, case_id),
        )
        if cursor.rowcount:
            conn.execute(
                "UPDATE campaigns SET updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (campaign_id,),
            )
            _campaign_audit(
                conn,
                campaign_id,
                user["id"],
                "campaign.case_detached",
                str(campaign_id),
                case_id,
            )
    return {"ok": True}


@router.get("/campaigns/{campaign_id}/cases")
def campaign_cases(
    campaign_id: int,
    user: User,
    q: str = Query("", max_length=500),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with db() as conn:
        _exists(conn, "campaigns", campaign_id, "Campagne introuvable")
        return _page(
            conn,
            CASE_SELECT
            + """ JOIN campaign_cases cc ON cc.case_id=c.id
            WHERE cc.campaign_id=? AND (c.title LIKE ? ESCAPE '\\' OR c.description LIKE ? ESCAPE '\\')
            ORDER BY c.updated_at DESC,c.id DESC""",
            (campaign_id, _pattern(q), _pattern(q)),
            page,
            page_size,
        )


@router.get("/campaigns/{campaign_id}/iocs")
def campaign_iocs(
    campaign_id: int,
    user: User,
    q: str = Query("", max_length=500),
    kind: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with db() as conn:
        _exists(conn, "campaigns", campaign_id, "Campagne introuvable")
        return _page(
            conn,
            IOC_SELECT
            + """ JOIN campaign_cases cc ON cc.case_id=a.case_id
            WHERE cc.campaign_id=? AND i.value LIKE ? ESCAPE '\\' AND (?='' OR i.kind=?)
            GROUP BY i.id HAVING count(DISTINCT a.case_id)>=2 ORDER BY case_count DESC,i.id DESC""",
            (campaign_id, _pattern(q), kind, kind),
            page,
            page_size,
        )


@router.get("/campaigns/{campaign_id}/events")
def campaign_events(
    campaign_id: int,
    user: User,
    q: str = Query("", max_length=500),
    action: str = "",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with db() as conn:
        _exists(conn, "campaigns", campaign_id, "Campagne introuvable")
        return _page(
            conn,
            """SELECT e.*,u.username FROM events e LEFT JOIN users u ON u.id=e.actor_id
            WHERE (EXISTS(SELECT 1 FROM campaign_events ce WHERE ce.campaign_id=? AND ce.event_id=e.id)
              OR EXISTS(SELECT 1 FROM campaign_cases cc WHERE cc.campaign_id=? AND cc.case_id=e.case_id))
            AND (?='' OR e.action=?) AND (e.action LIKE ? ESCAPE '\\' OR e.detail LIKE ? ESCAPE '\\')
            ORDER BY e.id DESC""",
            (campaign_id, campaign_id, action, action, _pattern(q), _pattern(q)),
            page,
            page_size,
        )


REASON_LABELS = {
    "subject": "Same normalized subject",
    "sender": "Same sender address",
    "sender_domain": "Same sender domain",
    "reply_to": "Same Reply-To address",
    "reply_to_domain": "Same Reply-To domain",
    "message_id": "Same Message-ID",
    "attachment_name": "Same attachment name",
    "sha256": "Same attachment SHA-256",
    "body_sha256": "Same normalized body SHA-256",
    "original_sha256": "Same original SHA-256",
    "url": "Same URL",
    "domain": "Same domain",
    "ip": "Same IP address",
    "email": "Same email address",
}
SHARED_SIGNALS = """WITH all_signals AS (
    SELECT analysis_id,kind,value FROM analysis_signals
    UNION SELECT ai.analysis_id,i.kind,i.value FROM analysis_iocs ai JOIN iocs i ON i.id=ai.ioc_id
), shared AS (
    SELECT DISTINCT target.analysis_id,target.kind,target.value FROM all_signals source
    JOIN all_signals target ON target.kind=source.kind AND target.value=source.value
    WHERE source.analysis_id=? AND target.analysis_id<>?
) """


@router.get("/analyses/{analysis_id}/similarities")
def similarities(
    analysis_id: str,
    user: User,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with db() as conn:
        _exists(conn, "analyses", analysis_id, "Analyse introuvable")
        result = _page(
            conn,
            SHARED_SIGNALS
            + """SELECT a.id,a.case_id,a.subject,a.filename,a.status,a.created_at,
            c.title AS case_title,count(*) AS shared_signal_count FROM shared s JOIN analyses a ON a.id=s.analysis_id
            JOIN cases c ON c.id=a.case_id GROUP BY a.id ORDER BY shared_signal_count DESC,a.created_at DESC,a.id DESC""",
            (analysis_id, analysis_id),
            page,
            page_size,
        )
        by_id = {item["id"]: item for item in result["items"]}
        for item in result["items"]:
            item["reasons"] = []
        if by_id:
            placeholders = ",".join("?" for _ in by_id)
            rows = conn.execute(
                SHARED_SIGNALS
                + f"SELECT analysis_id,kind,value FROM shared WHERE analysis_id IN ({placeholders}) ORDER BY kind,value",
                (analysis_id, analysis_id, *by_id),
            )
            for row in rows:
                by_id[row["analysis_id"]]["reasons"].append(
                    {
                        "kind": row["kind"],
                        "value": row["value"],
                        "label": REASON_LABELS.get(row["kind"], "Same indicator"),
                    }
                )
        result["method"] = (
            "Exact shared signals; this is an investigation lead, not a verdict or an automatic case merge."
        )
        return result


@router.get("/search")
def search(
    user: User,
    q: str = Query("", max_length=500),
    type: Literal["all", "case", "analysis", "ioc", "campaign"] = "all",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    pattern = _pattern(q)
    fragments = {
        "case": (
            """SELECT 'case' AS type,c.id,c.title,c.description AS subtitle,'/cases/'||c.id AS url,c.created_at AS sort_at
            FROM cases c WHERE c.title LIKE ? ESCAPE '\\' OR c.description LIKE ? ESCAPE '\\'""",
            [pattern] * 2,
        ),
        "analysis": (
            """SELECT 'analysis' AS type,a.id,CASE WHEN a.subject='' THEN a.filename ELSE a.subject END AS title,
            a.filename AS subtitle,'/analyses/'||a.id AS url,a.created_at AS sort_at FROM analyses a
            WHERE a.subject LIKE ? ESCAPE '\\' OR a.filename LIKE ? ESCAPE '\\' OR a.sha256 LIKE ? ESCAPE '\\'
              OR EXISTS(SELECT 1 FROM analysis_signals s WHERE s.analysis_id=a.id AND s.value LIKE ? ESCAPE '\\')
              OR EXISTS(SELECT 1 FROM analysis_iocs ai JOIN iocs i ON i.id=ai.ioc_id WHERE ai.analysis_id=a.id AND i.value LIKE ? ESCAPE '\\')""",
            [pattern] * 5,
        ),
        "ioc": (
            """SELECT 'ioc' AS type,i.id,i.value AS title,i.kind AS subtitle,'/iocs/'||i.id AS url,'' AS sort_at
            FROM iocs i WHERE i.value LIKE ? ESCAPE '\\'""",
            [pattern],
        ),
        "campaign": (
            """SELECT 'campaign' AS type,c.id,c.name AS title,c.description AS subtitle,'/campaigns/'||c.id AS url,c.created_at AS sort_at
            FROM campaigns c WHERE c.deleted_at IS NULL AND (c.name LIKE ? ESCAPE '\\' OR c.description LIKE ? ESCAPE '\\'
              OR c.tags LIKE ? ESCAPE '\\')""",
            [pattern] * 3,
        ),
    }
    selected = list(fragments.values()) if type == "all" else [fragments[type]]
    sql = (
        "SELECT * FROM ("
        + " UNION ALL ".join(part[0] for part in selected)
        + ") ORDER BY sort_at DESC,type,id DESC"
    )
    params = tuple(value for part in selected for value in part[1])
    with db() as conn:
        return _page(conn, sql, params, page, page_size)
