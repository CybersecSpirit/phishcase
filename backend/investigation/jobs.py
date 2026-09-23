"""Durable SQLite queue with atomic claims and fenced, expiring leases."""

import base64
import hashlib
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from loguru import logger

from .assessment import summarize
from .evidence import original, storage
from .processing import extract_iocs
from .store import audit, db

ingestion_guard: ContextVar = ContextVar("phishcase_ingestion_guard", default=None)


@contextmanager
def rollback_files():
    keys = []
    try:
        yield keys
    except BaseException:
        for key in keys:
            storage().delete(key)
        raise


def initialize_jobs(conn):
    conn.executescript("""
      CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL UNIQUE REFERENCES analyses(id),
        state TEXT NOT NULL DEFAULT 'queued', attempts INTEGER NOT NULL DEFAULT 0,
        max_attempts INTEGER NOT NULL DEFAULT 3, available_at REAL NOT NULL DEFAULT 0,
        lease_until REAL, lease_token TEXT, error TEXT, created_at REAL NOT NULL,
        updated_at REAL NOT NULL, idempotency_key TEXT, created_by INTEGER NOT NULL REFERENCES users(id),
        UNIQUE(created_by,idempotency_key));
      CREATE INDEX IF NOT EXISTS jobs_ready ON jobs(state,available_at);
      CREATE TABLE IF NOT EXISTS worker_heartbeats (id TEXT PRIMARY KEY, seen REAL NOT NULL);
    """)
    # Only pre-queue unfinished analyses need adoption. Completed originals stay intact.
    for row in conn.execute(
        "SELECT id,created_by FROM analyses WHERE status IN ('queued','running') AND id NOT IN (SELECT analysis_id FROM jobs)"
    ).fetchall():
        now = time.time()
        conn.execute(
            "INSERT INTO jobs(id,analysis_id,created_at,updated_at,created_by) VALUES (?,?,?,?,?)",
            (uuid4().hex, row["id"], now, now, row["created_by"]),
        )
        conn.execute("UPDATE analyses SET status='queued' WHERE id=?", (row["id"],))


def enqueue(
    raw, filename, user, case_id=None, ingestion_source="upload", idempotency_key=None
):
    if idempotency_key is not None and (
        not idempotency_key or len(idempotency_key) > 128
    ):
        raise ValueError("Invalid Idempotency-Key")
    digest = hashlib.sha256(raw).hexdigest()
    now = time.time()
    with rollback_files() as new_files, db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if idempotency_key:
            previous = conn.execute(
                "SELECT a.id,a.sha256,a.case_id FROM jobs j JOIN analyses a ON a.id=j.analysis_id WHERE j.created_by=? AND j.idempotency_key=?",
                (user["id"], idempotency_key),
            ).fetchone()
            if previous:
                if previous["sha256"] != digest or (
                    case_id is not None and previous["case_id"] != case_id
                ):
                    raise ValueError("Idempotency-Key already used for another upload")
                return previous["id"]
        auto_title = None
        if case_id is None:
            auto_title = f"{datetime.now(UTC):%Y-%m-%d} · {filename}"[:200]
            case_id = conn.execute(
                "INSERT INTO cases(title,created_by,assignee_id) VALUES (?,?,?)",
                (auto_title, user["id"], user["id"]),
            ).lastrowid
            audit(conn, user["id"], "case.created", case_id, auto_title)
        elif not conn.execute("SELECT id FROM cases WHERE id=?", (case_id,)).fetchone():
            raise LookupError("Case not found")
        guard = ingestion_guard.get()
        if guard is not None:
            guard(conn, user, len(raw), case_id)
        item = storage().put(raw)
        new_files.append(item.key)
        analysis_id = str(uuid4())
        conn.execute(
            "INSERT INTO analyses(id,case_id,filename,sha256,status,created_by,source_ref,size,ingestion_source,auto_title) VALUES (?,?,?,?,'queued',?,?,?,?,?)",
            (
                analysis_id,
                case_id,
                filename,
                item.sha256,
                user["id"],
                item.key,
                item.size,
                ingestion_source,
                auto_title,
            ),
        )
        conn.execute(
            "INSERT INTO jobs(id,analysis_id,max_attempts,created_at,updated_at,created_by,idempotency_key) VALUES (?,?,?,?,?,?,?)",
            (
                uuid4().hex,
                analysis_id,
                max(1, min(10, int(os.environ.get("JOB_MAX_ATTEMPTS", "3")))),
                now,
                now,
                user["id"],
                idempotency_key,
            ),
        )
        audit(conn, user["id"], "analysis.queued", case_id, analysis_id)
        return analysis_id


def recover(conn, now):
    for job in conn.execute(
        "SELECT * FROM jobs WHERE state='running' AND lease_until<?", (now,)
    ).fetchall():
        state = "failed" if job["attempts"] >= job["max_attempts"] else "queued"
        reason = (
            "Worker interrupted; retry limit reached"
            if state == "failed"
            else "Worker interrupted; queued again"
        )
        conn.execute(
            "UPDATE jobs SET state=?,lease_token=NULL,lease_until=NULL,error=?,updated_at=? WHERE id=?",
            (state, reason, now, job["id"]),
        )
        conn.execute(
            "UPDATE analyses SET status=?,error=? WHERE id=?",
            (state, reason, job["analysis_id"]),
        )


def claim():
    now = time.time()
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        recover(conn, now)
        job = conn.execute(
            "SELECT * FROM jobs WHERE state='queued' AND available_at<=? ORDER BY created_at,id LIMIT 1",
            (now,),
        ).fetchone()
        if not job:
            return None
        token = uuid4().hex
        lease = now + int(os.environ.get("JOB_TIMEOUT_SECONDS", "180")) + 60
        conn.execute(
            "UPDATE jobs SET state='running',attempts=attempts+1,lease_token=?,lease_until=?,updated_at=? WHERE id=?",
            (token, lease, now, job["id"]),
        )
        conn.execute(
            "UPDATE analyses SET status='running',error=NULL WHERE id=?",
            (job["analysis_id"],),
        )
        result = dict(job)
        result.update(lease_token=token, attempts=job["attempts"] + 1)
        return result


def analyze_isolated(raw: bytes, child_environment=None) -> dict:
    """Hard timeout applies even to blocking/decompression parser code."""
    with tempfile.TemporaryDirectory(prefix="phishcase-parser-") as directory:
        source = Path(directory) / "original"
        output = Path(directory) / "report.json"
        source.write_bytes(raw)
        source.chmod(0o600)
        runtime_keys = {
            "PATH",
            "LANG",
            "LC_ALL",
            "HOME",
            "TMPDIR",
            "SYSTEMROOT",
            "VIRTUAL_ENV",
            "PYTHONPATH",
            "DYLD_LIBRARY_PATH",
            "LD_LIBRARY_PATH",
        }
        parser_keys = {
            "CONNECTIVITY_MODE",
            "PARSER_MEMORY_MB",
            "SPAMASSASSIN_HOST",
            "SPAMASSASSIN_PORT",
            "SPAMASSASSIN_TIMEOUT",
            "VIRUSTOTAL_API_KEY",
            "URLSCAN_API_KEY",
            "EMAIL_REP_API_KEY",
        }
        environment = {k: v for k, v in os.environ.items() if k in runtime_keys}
        settings = child_environment if child_environment is not None else os.environ
        environment.update({k: v for k, v in settings.items() if k in parser_keys})
        if child_environment is not None:
            environment["PHISHCASE_DISABLE_DOTENV"] = "true"
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "backend.investigation.analyzer_task",
                str(source),
                str(output),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            env=environment,
        )
        try:
            process.wait(timeout=int(os.environ.get("JOB_TIMEOUT_SECONDS", "180")))
            if process.returncode or not output.exists():
                raise ValueError("Parser rejected the file or exceeded resource limits")
            if output.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("Report exceeds size limit")
            return json.loads(output.read_text())
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise


def finish(job, document=None, error=None):
    now = time.time()
    with rollback_files() as new_files, db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT * FROM jobs WHERE id=? AND state='running' AND lease_token=? AND lease_until>=?",
            (job["id"], job["lease_token"], now),
        ).fetchone()
        if not current:
            return False  # A stale worker must never overwrite a newer attempt.
        row = conn.execute(
            "SELECT * FROM analyses WHERE id=?", (job["analysis_id"],)
        ).fetchone()
        if error:
            state = (
                "failed" if current["attempts"] >= current["max_attempts"] else "queued"
            )
            conn.execute(
                "UPDATE jobs SET state=?,error=?,available_at=?,updated_at=?,lease_token=NULL,lease_until=NULL WHERE id=?",
                (state, error, now + min(60, 2 ** current["attempts"]), now, job["id"]),
            )
            conn.execute(
                "UPDATE analyses SET status=?,error=?,finished_at=CASE WHEN ?='failed' THEN CURRENT_TIMESTAMP ELSE NULL END WHERE id=?",
                (state, error, state, row["id"]),
            )
            audit(
                conn, row["created_by"], "analysis." + state, row["case_id"], row["id"]
            )
            return True
        for index, item in enumerate(document.get("eml", {}).get("attachments", [])):
            raw = base64.b64decode(item.pop("raw", ""), validate=True)
            evidence = storage().put(raw)
            new_files.append(evidence.key)
            item["size"] = evidence.size
            item.setdefault("hash", {})["sha256"] = evidence.sha256
            conn.execute(
                "INSERT OR REPLACE INTO evidence_attachments VALUES (?,?,?,?,?)",
                (row["id"], index, evidence.key, evidence.sha256, evidence.size),
            )
        document.setdefault("assessment", summarize(document))
        subject = document.get("eml", {}).get("header", {}).get("subject") or ""
        conn.execute(
            "UPDATE analyses SET status='completed',subject=?,result=?,error=NULL,finished_at=CURRENT_TIMESTAMP WHERE id=?",
            (subject, json.dumps(document), row["id"]),
        )
        if row["auto_title"]:
            title = f"{row['created_at'][:10]} · {' '.join((subject or row['filename']).split())}"[
                :200
            ]
            conn.execute(
                "UPDATE cases SET title=?,updated_at=CURRENT_TIMESTAMP WHERE id=? AND title=?",
                (title, row["case_id"], row["auto_title"]),
            )
        for kind, value in extract_iocs(document):
            conn.execute(
                "INSERT OR IGNORE INTO iocs(kind,value) VALUES (?,?)", (kind, value)
            )
            conn.execute(
                "INSERT OR IGNORE INTO analysis_iocs SELECT ?,id FROM iocs WHERE kind=? AND value=?",
                (row["id"], kind, value),
            )
        from .investigations import index_analysis

        index_analysis(conn, row["id"], document)
        conn.execute(
            "UPDATE jobs SET state='completed',error=NULL,updated_at=?,lease_until=NULL,lease_token=NULL WHERE id=?",
            (now, job["id"]),
        )
        audit(conn, row["created_by"], "analysis.completed", row["case_id"], row["id"])
        return True


def run_once(analyzer=analyze_isolated):
    job = claim()
    if not job:
        return False
    logger.bind(job_id=job["id"], analysis_id=job["analysis_id"]).info(
        "analysis.started"
    )
    try:
        with db() as conn:
            raw = original(conn, job["analysis_id"])
        document = analyzer(raw)
        finish(job, document=document)
    except Exception:
        finish(
            job,
            error="Analysis failed or timed out; original preserved. Retry available.",
        )
        logger.bind(job_id=job["id"], analysis_id=job["analysis_id"]).warning(
            "analysis.failed"
        )
    return True


def main():
    from backend import settings

    from .store import initialize

    logger.remove()
    logger.add(
        settings.LOG_FILE,
        level=settings.LOG_LEVEL,
        serialize=True,
        backtrace=False,
        diagnose=False,
    )
    initialize()
    worker_id = uuid4().hex
    stop = False

    def shutdown(signum, frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    while not stop:
        with db() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO worker_heartbeats VALUES (?,?)",
                (worker_id, time.time()),
            )
            conn.execute(
                "DELETE FROM worker_heartbeats WHERE seen<?", (time.time() - 600,)
            )
        if not run_once():
            time.sleep(1)


if __name__ == "__main__":
    main()
