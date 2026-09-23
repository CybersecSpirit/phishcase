"""Single-team SQLite metadata, with immutable originals in EvidenceStorage."""

import fcntl
import hashlib
import hmac
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


def _initialize():
    with db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
        )
        latest = conn.execute(
            "SELECT COALESCE(MAX(version),0) FROM schema_migrations"
        ).fetchone()[0]
        if latest > 2026092301:
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
          id TEXT PRIMARY KEY, case_id INTEGER NOT NULL REFERENCES cases(id), filename TEXT NOT NULL,
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

        initialize_tokens(conn)
        initialize_evidence(conn)
        initialize_jobs(conn)
        initialize_investigations(conn)
        initialize_enrichments(conn)
        if "locale" not in {r[1] for r in conn.execute("PRAGMA table_info(users)")}:
            conn.execute(
                "ALTER TABLE users ADD COLUMN locale TEXT NOT NULL DEFAULT 'fr'"
            )
        conn.execute(
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES (2026092301)"
        )


def audit(conn, actor, action, case_id=None, detail=""):
    conn.execute(
        "INSERT INTO events(actor_id,case_id,action,detail) VALUES (?,?,?,?)",
        (actor, case_id, action, detail),
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
