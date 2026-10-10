"""Independent emails and optional campaigns; legacy case records are an archive."""

import json
import re
from typing import Literal

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from .auth import User, Writer
from .investigations import VerdictValue, _campaign, _exists, _page, _pattern
from .store import audit, db
from .workflows import conflict, validate_owner

router = APIRouter()
VERSION = 2026101002
SCHEMA = """
CREATE TABLE IF NOT EXISTS campaign_analyses (
 campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
 analysis_id TEXT NOT NULL REFERENCES analyses(id) ON DELETE CASCADE,
 PRIMARY KEY(campaign_id,analysis_id));
CREATE INDEX IF NOT EXISTS campaign_analyses_email ON campaign_analyses(analysis_id,campaign_id);
CREATE TABLE IF NOT EXISTS campaign_notes (
 id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL REFERENCES campaigns(id),
 author_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 legacy_note_id INTEGER UNIQUE);
CREATE TABLE IF NOT EXISTS legacy_case_links (
 case_id INTEGER PRIMARY KEY REFERENCES cases(id),
 campaign_id INTEGER REFERENCES campaigns(id),
 analysis_id TEXT REFERENCES analyses(id) ON DELETE SET NULL);
"""


def meaningful_legacy_case(conn, case, emails):
    auto = False
    if len(emails) == 1 and emails[0]["auto_title"]:
        email = emails[0]
        title = f"{email['created_at'][:10]} · {' '.join((email['subject'] or email['filename']).split())}"[
            :200
        ]
        auto = case["title"] in (email["auto_title"], title)
    # A custom title is useful context, even when it resembles the automatic date prefix.
    context = any(
        conn.execute(sql, (case["id"],)).fetchone()[0]
        for sql in (
            "SELECT count(*) FROM notes WHERE case_id=?",
            "SELECT count(*) FROM case_actions WHERE case_id=?",
            "SELECT count(*) FROM reporter_replies WHERE case_id=? AND analysis_id IS NULL",
            "SELECT count(*) FROM intelligence_links WHERE case_id=?",
        )
    )
    return (
        not auto
        or context
        or case["status"] != "open"
        or case["priority"] != "medium"
        or case["revision"] > 1
        or bool(case["description"])
        or case["assignee_id"] != emails[0]["created_by"]
    )


def migrate_legacy(conn):
    """Idempotent data projection; never delete or rewrite original evidence."""
    for row in conn.execute("SELECT * FROM cases ORDER BY id").fetchall():
        case = dict(row)
        if conn.execute(
            "SELECT case_id FROM legacy_case_links WHERE case_id=?", (case["id"],)
        ).fetchone():
            continue
        emails = conn.execute(
            "SELECT id,created_by,auto_title,created_at,subject,filename FROM analyses WHERE case_id=?",
            (case["id"],),
        ).fetchall()
        meaningful = meaningful_legacy_case(conn, case, emails)
        campaign_id = None
        if meaningful:
            campaign_id = conn.execute(
                "INSERT INTO campaigns(name,description,tags,status,created_by,created_at,updated_at,priority,assignee_id,revision) VALUES (?,?,?, ?,?,?,?,?,?,?)",
                (
                    case["title"],
                    case["description"],
                    "[]",
                    "active" if case["status"] == "open" else case["status"],
                    case["created_by"],
                    case["created_at"],
                    case["updated_at"],
                    case["priority"],
                    case["assignee_id"],
                    case["revision"],
                ),
            ).lastrowid
        conn.execute(
            "INSERT INTO legacy_case_links(case_id,campaign_id,analysis_id) VALUES (?,?,?)",
            (case["id"], campaign_id, emails[0]["id"] if len(emails) == 1 else None),
        )
        memberships = [
            r[0]
            for r in conn.execute(
                "SELECT campaign_id FROM campaign_cases WHERE case_id=?", (case["id"],)
            )
        ]
        if campaign_id is not None:
            memberships.append(campaign_id)
            for note in conn.execute(
                "SELECT * FROM notes WHERE case_id=?", (case["id"],)
            ).fetchall():
                conn.execute(
                    "INSERT INTO campaign_notes(campaign_id,author_id,body,created_at,legacy_note_id) VALUES (?,?,?,?,?)",
                    (
                        campaign_id,
                        note["author_id"],
                        note["body"],
                        note["created_at"],
                        note["id"],
                    ),
                )
            conn.execute(
                "UPDATE case_actions SET campaign_id=? WHERE case_id=?",
                (campaign_id, case["id"]),
            )
            conn.execute(
                "UPDATE reporter_replies SET campaign_id=? WHERE case_id=? AND analysis_id IS NULL",
                (campaign_id, case["id"]),
            )
            conn.execute(
                "UPDATE intelligence_links SET campaign_id=? WHERE case_id=? AND campaign_id IS NULL",
                (campaign_id, case["id"]),
            )
        for email in emails:
            for member in memberships:
                conn.execute(
                    "INSERT OR IGNORE INTO campaign_analyses(campaign_id,analysis_id) VALUES (?,?)",
                    (member, email["id"]),
                )
        migrate_events(conn, case["id"], emails, memberships)


def migrate_events(conn, case_id, emails, memberships):
    for event in conn.execute(
        "SELECT id,action,detail FROM events WHERE case_id=?", (case_id,)
    ).fetchall():
        if len(emails) == 1:
            conn.execute(
                "UPDATE events SET analysis_id=? WHERE id=?",
                (emails[0]["id"], event["id"]),
            )
        for member in memberships:
            conn.execute(
                "INSERT OR IGNORE INTO campaign_events(campaign_id,event_id) VALUES (?,?)",
                (member, event["id"]),
            )


def allow_independent_emails(conn):
    for table in ("analyses", "case_actions", "reporter_replies"):
        info = conn.execute(f"PRAGMA table_info({table})").fetchall()
        if any(r[1] == "case_id" and r[3] for r in info):
            sql = conn.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
            ).fetchone()[0]
            indexes = [
                r[0]
                for r in conn.execute(
                    "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL",
                    (table,),
                )
            ]
            sql = re.sub(
                r"CREATE TABLE\s+" + table,
                "CREATE TABLE " + table + "_new",
                sql,
                count=1,
                flags=re.I,
            )
            sql = re.sub(
                r"case_id INTEGER NOT NULL", "case_id INTEGER", sql, flags=re.I
            )
            conn.execute(sql)
            columns = ",".join('"' + r[1] + '"' for r in info)
            conn.execute(
                f"INSERT INTO {table}_new({columns}) SELECT {columns} FROM {table}"
            )
            conn.execute(f"DROP TABLE {table}")
            conn.execute(f"ALTER TABLE {table}_new RENAME TO {table}")
            for sql in indexes:
                conn.execute(sql)


def initialize_collections(conn):
    # The caller holds the application initialization lock. SQLite's table rebuild
    # is a single transaction with FK validation before commit; indexes survive.
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.execute("BEGIN IMMEDIATE")
        allow_independent_emails(conn)
        additions = {
            "campaigns": [
                ("priority", "TEXT NOT NULL DEFAULT 'medium'"),
                ("assignee_id", "INTEGER REFERENCES users(id)"),
                ("revision", "INTEGER NOT NULL DEFAULT 1"),
            ],
            "events": [
                ("analysis_id", "TEXT REFERENCES analyses(id) ON DELETE SET NULL")
            ],
            "case_actions": [
                ("campaign_id", "INTEGER REFERENCES campaigns(id)"),
                ("analysis_id", "TEXT REFERENCES analyses(id) ON DELETE SET NULL"),
            ],
            "reporter_replies": [("campaign_id", "INTEGER REFERENCES campaigns(id)")],
        }
        for table, fields in additions.items():
            columns = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
            for name, definition in fields:
                if name not in columns:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")
        for statement in SCHEMA.split(";"):
            if statement.strip():
                conn.execute(statement)
        migrate_legacy(conn)
        if conn.execute("PRAGMA foreign_key_check").fetchone():
            raise RuntimeError("Campaign migration failed foreign-key verification")
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES (?)", (VERSION,)
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA foreign_keys=ON")


SELECT = """SELECT c.*,u.username AS assignee,
 (SELECT count(*) FROM campaign_analyses ca WHERE ca.campaign_id=c.id) AS analysis_count,
 (SELECT count(*) FROM case_actions a WHERE a.campaign_id=c.id AND a.status IN ('todo','doing')) AS pending_actions
 FROM campaigns c LEFT JOIN users u ON u.id=c.assignee_id"""


class CampaignInput(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="", max_length=20000)
    tags: list[str] = Field(default_factory=list, max_length=50)
    status: str = Field(
        default="active", pattern="^(active|investigating|resolved|closed)$"
    )
    verdict: VerdictValue | None = None
    priority: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    assignee_id: int | None = None
    revision: int | None = Field(default=None, ge=1)
    analysis_ids: list[str] = Field(default_factory=list, max_length=200)

    @field_validator("name")
    @classmethod
    def nonblank(cls, value):
        if not value.strip():
            raise ValueError("Nom requis")
        return value.strip()

    @field_validator("tags")
    @classmethod
    def normalize_tags(cls, values):
        return sorted({value.strip().casefold() for value in values if value.strip()})


def campaign(conn, identity):
    row = conn.execute(
        SELECT + " WHERE c.id=? AND c.deleted_at IS NULL", (identity,)
    ).fetchone()
    if not row:
        raise HTTPException(404, "Campagne introuvable")
    return _campaign(dict(row))


def campaign_audit(conn, user, identity, action, detail=""):
    audit(conn, user["id"], action, detail=detail)
    conn.execute(
        "INSERT INTO campaign_events(campaign_id,event_id) VALUES (?,last_insert_rowid())",
        (identity,),
    )


def guard_campaign(conn, identity):
    pending = conn.execute(
        "SELECT count(*) FROM case_actions WHERE (campaign_id=? OR analysis_id IN (SELECT analysis_id FROM campaign_analyses WHERE campaign_id=?)) AND status IN ('todo','doing')",
        (identity, identity),
    ).fetchone()[0]
    undecided = conn.execute(
        """SELECT count(*) FROM analyses a JOIN campaign_analyses ca ON ca.analysis_id=a.id WHERE ca.campaign_id=? AND
     (a.status IN ('queued','running') OR (a.status='completed' AND COALESCE((SELECT action FROM analyst_decisions d WHERE d.analysis_id=a.id ORDER BY d.id DESC LIMIT 1),'reopened')='reopened'))""",
        (identity,),
    ).fetchone()[0]
    sending = conn.execute(
        """SELECT count(*) FROM reporter_replies r WHERE r.status='sending' AND (r.campaign_id=? OR r.analysis_id IN (SELECT analysis_id FROM campaign_analyses WHERE campaign_id=?))""",
        (identity, identity),
    ).fetchone()[0]
    if pending or undecided or sending:
        raise HTTPException(
            409,
            "Clôture impossible : terminez les actions, qualifiez les messages et vérifiez les réponses en cours.",
        )


@router.get("/campaigns")
def campaigns(
    user: User,
    q: str = "",
    status: str = "",
    tag: str = "",
    scope: Literal["team", "mine"] = "team",
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with db() as conn:
        return _page(
            conn,
            SELECT
            + " WHERE c.deleted_at IS NULL AND (?='' OR c.status=?) AND (?='team' OR c.assignee_id=?) AND (c.name LIKE ? ESCAPE '\\' OR c.description LIKE ? ESCAPE '\\') AND (?='' OR c.tags LIKE ? ESCAPE '\\') ORDER BY c.updated_at DESC,c.id DESC",
            (
                status,
                status,
                scope,
                user["id"],
                _pattern(q),
                _pattern(q),
                tag,
                _pattern(tag),
            ),
            page,
            page_size,
            _campaign,
        )


@router.get("/campaigns/{identity}")
def get_campaign(identity: int, user: User):
    with db() as conn:
        return campaign(conn, identity)


def link_emails(conn, identity, ids, user):
    for analysis_id in dict.fromkeys(ids):
        _exists(conn, "analyses", analysis_id, "Analyse introuvable")
    for analysis_id in dict.fromkeys(ids):
        conn.execute(
            "INSERT OR IGNORE INTO campaign_analyses(campaign_id,analysis_id) VALUES (?,?)",
            (identity, analysis_id),
        )
        campaign_audit(conn, user, identity, "campaign.email_attached", analysis_id)


@router.post("/campaigns", status_code=201)
def create_campaign(data: CampaignInput, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        owner = (
            data.assignee_id if "assignee_id" in data.model_fields_set else user["id"]
        )
        validate_owner(conn, owner)
        identity = conn.execute(
            "INSERT INTO campaigns(name,description,tags,status,verdict,priority,assignee_id,created_by) VALUES (?,?,?,?,?,?,?,?)",
            (
                data.name.strip(),
                data.description,
                json.dumps(data.tags),
                "active",
                data.verdict,
                data.priority,
                owner,
                user["id"],
            ),
        ).lastrowid
        link_emails(conn, identity, data.analysis_ids, user)
        if data.status == "closed":
            guard_campaign(conn, identity)
        conn.execute(
            "UPDATE campaigns SET status=? WHERE id=?", (data.status, identity)
        )
        campaign_audit(conn, user, identity, "campaign.created", data.name)
        return campaign(conn, identity)


@router.delete("/campaigns/{identity}")
def archive_campaign(identity: int, user: Writer, revision: int = Query(ge=1)):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = campaign(conn, identity)
        if row["revision"] != revision:
            conflict()
        guard_campaign(conn, identity)
        conn.execute(
            "UPDATE campaigns SET deleted_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP,revision=revision+1 WHERE id=?",
            (identity,),
        )
        campaign_audit(conn, user, identity, "campaign.deleted", str(identity))
        return {"ok": True}


@router.put("/campaigns/{identity}")
def update_campaign(identity: int, data: CampaignInput, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = campaign(conn, identity)
        if data.revision != row["revision"]:
            conflict()
        validate_owner(conn, data.assignee_id)
        if data.status == "closed":
            guard_campaign(conn, identity)
        conn.execute(
            "UPDATE campaigns SET name=?,description=?,tags=?,status=?,verdict=?,priority=?,assignee_id=?,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (
                data.name.strip(),
                data.description,
                json.dumps(data.tags),
                data.status,
                data.verdict,
                data.priority,
                data.assignee_id,
                identity,
            ),
        )
        campaign_audit(conn, user, identity, "campaign.updated", data.model_dump_json())
        return campaign(conn, identity)


class Membership(BaseModel):
    analysis_ids: list[str] = Field(min_length=1, max_length=200)
    revision: int = Field(ge=1)


@router.post("/campaigns/{identity}/emails")
def add_emails(identity: int, data: Membership, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = campaign(conn, identity)
        if data.revision != row["revision"]:
            conflict()
        if row["status"] == "closed":
            raise HTTPException(
                409, "Rouvrez la campagne avant de rattacher des emails"
            )
        link_emails(conn, identity, data.analysis_ids, user)
        conn.execute(
            "UPDATE campaigns SET revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (identity,),
        )
        return campaign(conn, identity)


@router.delete("/campaigns/{identity}/emails/{analysis_id}")
def remove_email(
    identity: int, analysis_id: str, user: Writer, revision: int = Query(ge=1)
):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = campaign(conn, identity)
        if revision != row["revision"]:
            conflict()
        if row["status"] == "closed":
            raise HTTPException(409, "Rouvrez la campagne avant de détacher un email")
        conn.execute(
            "DELETE FROM campaign_analyses WHERE campaign_id=? AND analysis_id=?",
            (identity, analysis_id),
        )
        conn.execute(
            "UPDATE campaigns SET revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (identity,),
        )
        campaign_audit(conn, user, identity, "campaign.email_detached", analysis_id)
        return campaign(conn, identity)


@router.get("/campaigns/{identity}/emails")
def emails(
    identity: int,
    user: User,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
):
    with db() as conn:
        campaign(conn, identity)
        return _page(
            conn,
            "SELECT a.id,a.subject,a.filename,a.status,a.created_at FROM analyses a JOIN campaign_analyses ca ON ca.analysis_id=a.id WHERE ca.campaign_id=? ORDER BY a.created_at DESC,a.id DESC",
            (identity,),
            page,
            page_size,
        )


@router.get("/analyses/{analysis_id}/campaigns")
def email_campaigns(analysis_id: str, user: User):
    with db() as conn:
        _exists(conn, "analyses", analysis_id, "Analyse introuvable")
        return [
            _campaign(dict(r))
            for r in conn.execute(
                SELECT
                + " JOIN campaign_analyses ca ON ca.campaign_id=c.id WHERE ca.analysis_id=? AND c.deleted_at IS NULL ORDER BY c.id DESC",
                (analysis_id,),
            )
        ]


@router.get("/campaigns/{identity}/events")
def events(
    identity: int,
    user: User,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    q: str = "",
    action: str = "",
):
    with db() as conn:
        campaign(conn, identity)
        return _page(
            conn,
            """SELECT e.*,u.username FROM events e LEFT JOIN users u ON u.id=e.actor_id
         WHERE (EXISTS(SELECT 1 FROM campaign_events ce WHERE ce.campaign_id=? AND ce.event_id=e.id)
         OR e.analysis_id IN (SELECT analysis_id FROM campaign_analyses WHERE campaign_id=?))
         AND (?='' OR e.action=?) AND (e.action LIKE ? ESCAPE '\\' OR e.detail LIKE ? ESCAPE '\\') ORDER BY e.id DESC""",
            (identity, identity, action, action, _pattern(q), _pattern(q)),
            page,
            page_size,
        )


@router.get("/campaigns/{identity}/iocs")
def iocs(
    identity: int,
    user: User,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    q: str = "",
    kind: str = "",
):
    with db() as conn:
        campaign(conn, identity)
        return _page(
            conn,
            """SELECT i.*,count(DISTINCT ca.analysis_id) AS analysis_count FROM iocs i
         JOIN analysis_iocs ai ON ai.ioc_id=i.id JOIN campaign_analyses ca ON ca.analysis_id=ai.analysis_id
         WHERE ca.campaign_id=? AND i.value LIKE ? ESCAPE '\\' AND (?='' OR i.kind=?) GROUP BY i.id ORDER BY analysis_count DESC,i.id DESC""",
            (identity, _pattern(q), kind, kind),
            page,
            page_size,
        )


class Note(BaseModel):
    body: str = Field(min_length=1, max_length=20000)


@router.get("/campaigns/{identity}/notes")
def notes(identity: int, user: User):
    with db() as conn:
        campaign(conn, identity)
        return [
            dict(r)
            for r in conn.execute(
                "SELECT n.*,u.username FROM campaign_notes n JOIN users u ON u.id=n.author_id WHERE campaign_id=? ORDER BY n.id DESC",
                (identity,),
            )
        ]


@router.post("/campaigns/{identity}/notes", status_code=201)
def add_note(identity: int, data: Note, user: Writer):
    with db() as conn:
        campaign(conn, identity)
        conn.execute(
            "INSERT INTO campaign_notes(campaign_id,author_id,body) VALUES (?,?,?)",
            (identity, user["id"], data.body),
        )
        campaign_audit(conn, user, identity, "campaign.note_added")
    return {"ok": True}


@router.get("/campaigns/{identity}/actions")
def campaign_actions(identity: int, user: User):
    from .workflows import ACTION_SELECT

    with db() as conn:
        campaign(conn, identity)
        return [
            dict(r)
            for r in conn.execute(
                ACTION_SELECT
                + " WHERE a.campaign_id=? OR a.analysis_id IN (SELECT analysis_id FROM campaign_analyses WHERE campaign_id=?) ORDER BY a.id DESC",
                (identity, identity),
            )
        ]


@router.get("/analyses/{analysis_id}/actions")
def email_actions(analysis_id: str, user: User):
    from .workflows import ACTION_SELECT

    with db() as conn:
        _exists(conn, "analyses", analysis_id, "Analyse introuvable")
        return [
            dict(r)
            for r in conn.execute(
                ACTION_SELECT + " WHERE a.analysis_id=? ORDER BY a.id DESC",
                (analysis_id,),
            )
        ]


from .workflows import ActionInput, ReplyInput  # noqa: E402


@router.post("/campaigns/{identity}/actions", status_code=201)
def new_campaign_action(identity: int, data: ActionInput, user: Writer):
    from .workflows import create_action

    return create_action(None, data, user, campaign_id=identity)


@router.post("/analyses/{analysis_id}/actions", status_code=201)
def new_email_action(analysis_id: str, data: ActionInput, user: Writer):
    from .workflows import create_action

    return create_action(None, data, user, analysis_id=analysis_id)


def scope_replies(user, campaign_id=None, analysis_id=None):
    from .workflows import reply_transport, workflow_scope

    with db() as conn:
        workflow_scope(conn, campaign_id=campaign_id, analysis_id=analysis_id)
        return {
            "transport_configured": reply_transport() is not None,
            "items": [
                dict(r)
                for r in conn.execute(
                    "SELECT * FROM reporter_replies WHERE (? IS NOT NULL AND analysis_id=?) OR (? IS NOT NULL AND (campaign_id=? OR analysis_id IN (SELECT analysis_id FROM campaign_analyses WHERE campaign_id=?))) ORDER BY id DESC",
                    (analysis_id, analysis_id, campaign_id, campaign_id, campaign_id),
                )
            ],
        }


@router.get("/campaigns/{identity}/replies")
def campaign_replies(identity: int, user: User):
    return scope_replies(user, campaign_id=identity)


@router.get("/analyses/{analysis_id}/replies")
def email_replies(analysis_id: str, user: User):
    return scope_replies(user, analysis_id=analysis_id)


@router.post("/campaigns/{identity}/replies", status_code=201)
def new_campaign_reply(identity: int, data: ReplyInput, user: Writer):
    from .workflows import create_reply

    return create_reply(None, data, user, campaign_id=identity)


@router.post("/analyses/{analysis_id}/replies", status_code=201)
def new_email_reply(analysis_id: str, data: ReplyInput, user: Writer):
    from .workflows import create_reply

    if data.analysis_id is not None and data.analysis_id != analysis_id:
        raise HTTPException(422, "Le mail de cette réponse ne peut pas être changé")
    return create_reply(
        None, data.model_copy(update={"analysis_id": analysis_id}), user
    )


@router.get("/legacy/cases/{identity}")
def legacy(identity: int, user: User):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM legacy_case_links WHERE case_id=?", (identity,)
        ).fetchone()
        if not row:
            raise HTTPException(404, "Ancien lien introuvable")
        return {
            **dict(row),
            "url": "/campaigns/" + str(row["campaign_id"])
            if row["campaign_id"]
            else "/analyses/" + str(row["analysis_id"])
            if row["analysis_id"]
            else "/analyses",
        }


@router.get("/dashboard")
def dashboard(user: User):
    from .api import dashboard as legacy_dashboard

    result = legacy_dashboard(user)
    with db() as conn:
        result["active_campaigns"] = conn.execute(
            "SELECT count(*) FROM campaigns WHERE deleted_at IS NULL AND status IN ('active','investigating')"
        ).fetchone()[0]
        result["campaigns_to_follow"] = [
            _campaign(dict(r))
            for r in conn.execute(
                SELECT
                + " WHERE c.deleted_at IS NULL AND c.status IN ('active','investigating') ORDER BY CASE c.priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,c.updated_at DESC,c.id DESC LIMIT 6"
            )
        ]
        result["analyses_to_review"] = [
            dict(r)
            for r in conn.execute("""SELECT a.id,a.subject,a.filename,a.status,a.created_at FROM analyses a WHERE a.status='failed' OR
         (a.status='completed' AND COALESCE((SELECT action FROM analyst_decisions d WHERE d.analysis_id=a.id ORDER BY d.id DESC LIMIT 1),'reopened')='reopened') ORDER BY a.created_at DESC,a.id DESC LIMIT 8""")
        ]
    return result
