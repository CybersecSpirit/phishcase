"""Single-team SQLite metadata, with immutable originals in EvidenceStorage."""

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path

database_factory: ContextVar = ContextVar("phishcase_database_factory", default=None)


def password_hash(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(
        password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1
    ).hex()
    return f"{salt}:{digest}"


def password_matches(password: str, encoded: str) -> bool:
    return hmac.compare_digest(password_hash(password, encoded.split(":")[0]), encoded)


@contextmanager
def db():
    factory = database_factory.get()
    if factory is not None:
        with factory() as connection:
            yield connection
        return
    path = Path(os.environ.get("INVESTIGATION_DB", "data/investigation.sqlite3"))
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def initialize():
    path = Path(os.environ.get("INVESTIGATION_DB", "data/investigation.sqlite3"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.with_suffix(path.suffix + ".init.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _initialize()
        from .collections import initialize_collections

        with db() as conn:
            initialize_collections(conn)


def _initialize():
    with db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        latest = conn.execute(
            "SELECT COALESCE(MAX(version),0) FROM schema_migrations"
        ).fetchone()[0]
        if latest > 2026101002:
            raise RuntimeError(
                "Database is newer than this application. Restore a compatible backup before rollback."
            )
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','analyst','viewer')),
          active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS sessions (
          token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS cases (
          id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
          status TEXT NOT NULL DEFAULT 'open', priority TEXT NOT NULL DEFAULT 'medium',
          assignee_id INTEGER REFERENCES users(id), created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS analyses (
          id TEXT PRIMARY KEY, case_id INTEGER REFERENCES cases(id), filename TEXT NOT NULL,
          sha256 TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued', subject TEXT NOT NULL DEFAULT '',
          result TEXT, error TEXT, source BLOB, created_by INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, finished_at TEXT);
        CREATE TABLE IF NOT EXISTS iocs (
          id INTEGER PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL,
          verdict TEXT NOT NULL DEFAULT 'unreviewed', UNIQUE(kind,value));
        CREATE TABLE IF NOT EXISTS analysis_iocs (
          analysis_id TEXT NOT NULL REFERENCES analyses(id), ioc_id INTEGER NOT NULL REFERENCES iocs(id),
          PRIMARY KEY(analysis_id,ioc_id));
        CREATE TABLE IF NOT EXISTS notes (
          id INTEGER PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id),
          author_id INTEGER NOT NULL REFERENCES users(id), body TEXT NOT NULL,
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS events (
          id INTEGER PRIMARY KEY, actor_id INTEGER REFERENCES users(id), case_id INTEGER REFERENCES cases(id),
          action TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS login_attempts (
          identity TEXT PRIMARY KEY, count INTEGER NOT NULL, window REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS mfa_challenges (
          token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS mfa_pending (
          user_id INTEGER PRIMARY KEY REFERENCES users(id), secret TEXT NOT NULL,
          session_token TEXT NOT NULL, expires REAL NOT NULL);
        CREATE TABLE IF NOT EXISTS mfa_recovery (
          user_id INTEGER NOT NULL REFERENCES users(id), digest TEXT NOT NULL,
          PRIMARY KEY(user_id,digest));
        CREATE INDEX IF NOT EXISTS analyses_case ON analyses(case_id);
        CREATE INDEX IF NOT EXISTS events_case ON events(case_id);
        """)

        columns = {row[1] for row in conn.execute("PRAGMA table_info(analyses)")}
        if "source" not in columns:
            conn.execute("ALTER TABLE analyses ADD COLUMN source BLOB")

        user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        for name, definition in (
            ("mfa_secret", "TEXT"),
            ("mfa_last_step", "INTEGER NOT NULL DEFAULT -1"),
        ):
            if name not in user_columns:
                conn.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")

        from .enrichment_api import initialize_enrichments
        from .evidence import initialize_evidence
        from .investigations import initialize_investigations
        from .jobs import initialize_jobs
        from .tokens import initialize_tokens
        from .workflows import initialize_workflows

        initialize_tokens(conn)
        initialize_evidence(conn)
        initialize_jobs(conn)
        initialize_investigations(conn)
        initialize_enrichments(conn)
        initialize_workflows(conn)
        if "locale" not in {r[1] for r in conn.execute("PRAGMA table_info(users)")}:
            conn.execute(
                "ALTER TABLE users ADD COLUMN locale TEXT NOT NULL DEFAULT 'fr'"
            )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES (2026092301)"
        )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES (2026101001)"
        )


def audit(conn, actor, action, case_id=None, detail=""):
    analysis_id, campaign_id = None, None
    if action.startswith("analysis."):
        try:
            value = json.loads(detail)
            candidate = value.get("analysis_id") if isinstance(value, dict) else detail
        except ValueError, TypeError:
            candidate = detail
        if conn.execute("SELECT id FROM analyses WHERE id=?", (candidate,)).fetchone():
            analysis_id = candidate
    if action.startswith(("reply.", "action.")):
        try:
            identity = int(detail)
        except ValueError, TypeError:
            try:
                value = json.loads(detail)
                identity = value.get("reply_id") or value.get("action_id")
            except ValueError, TypeError, AttributeError:
                identity = None
        table = "reporter_replies" if action.startswith("reply.") else "case_actions"
        row = conn.execute(
            f"SELECT analysis_id,campaign_id FROM {table} WHERE id=?", (identity,)
        ).fetchone()
        if row:
            analysis_id, campaign_id = row[0], row[1]
    conn.execute(
        "INSERT INTO events(actor_id,case_id,action,detail,analysis_id) VALUES (?,?,?,?,?)",
        (actor, case_id, action, detail, analysis_id),
    )
    if campaign_id is not None:
        conn.execute(
            "INSERT INTO campaign_events(campaign_id,event_id) VALUES (?,last_insert_rowid())",
            (campaign_id,),
        )


def create_admin(username: str, password: str):
    if len(password) < 12:
        raise ValueError("Le mot de passe doit contenir au moins 12 caractères.")
    initialize()
    with db() as conn:
        conn.execute(
            "INSERT INTO users(username,password,role) VALUES (?,?,?)",
            (username, password_hash(password), "admin"),
        )


if __name__ == "__main__":
    import getpass

    username = input("Identifiant administrateur : ").strip()
    if not username:
        raise SystemExit("Identifiant requis")
    create_admin(username, getpass.getpass("Mot de passe (12 caractères minimum) : "))
