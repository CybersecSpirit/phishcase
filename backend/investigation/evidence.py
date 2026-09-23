"""Immutable evidence storage. Keys are generated here, never from filenames."""

import base64
import hashlib
import json
import os
import re
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from uuid import uuid4

storage_factory: ContextVar = ContextVar("phishcase_storage_factory", default=None)


@dataclass(frozen=True)
class Evidence:
    key: str
    sha256: str
    size: int


class EvidenceStorage(Protocol):
    def put(self, content: bytes) -> Evidence: ...
    def read(self, key: str, sha256: str | None = None) -> bytes: ...
    def delete(self, key: str) -> None: ...


class FileEvidenceStorage:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def path(self, key: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", key):
            raise ValueError("Invalid evidence key")
        return self.root / key

    def put(self, content: bytes) -> Evidence:
        key = uuid4().hex
        path = self.path(key)
        descriptor = os.open(
            path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
        )
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return Evidence(key, hashlib.sha256(content).hexdigest(), len(content))

    def read(self, key: str, sha256: str | None = None) -> bytes:
        descriptor = os.open(self.path(key), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            content = stream.read()
        if sha256 and hashlib.sha256(content).hexdigest() != sha256:
            raise ValueError("Evidence integrity check failed")
        return content

    def delete(self, key: str) -> None:
        self.path(key).unlink(missing_ok=True)


def storage() -> EvidenceStorage:
    factory = storage_factory.get()
    if factory is not None:
        return factory()
    database = Path(os.environ.get("INVESTIGATION_DB", "data/investigation.sqlite3"))
    root = Path(os.environ.get("EVIDENCE_ROOT", str(database.parent / "evidence")))
    return FileEvidenceStorage(root)


def initialize_evidence(conn):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(analyses)")}
    for name, definition in (
        ("source_ref", "TEXT"),
        ("size", "INTEGER NOT NULL DEFAULT 0"),
        ("ingestion_source", "TEXT NOT NULL DEFAULT 'upload'"),
        ("metadata", "TEXT NOT NULL DEFAULT '{}'"),
        ("owner_scope", "TEXT NOT NULL DEFAULT 'community'"),
        ("auto_title", "TEXT"),
    ):
        if name not in columns:
            conn.execute(f"ALTER TABLE analyses ADD COLUMN {name} {definition}")
    conn.execute("""CREATE TABLE IF NOT EXISTS evidence_attachments (
        analysis_id TEXT NOT NULL REFERENCES analyses(id), position INTEGER NOT NULL,
        storage_key TEXT NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
        PRIMARY KEY(analysis_id,position))""")
    # Existing originals remain in their original transaction until persisted and
    # verified on disk. A rollback can only leave an unreferenced immutable file.
    for row in conn.execute(
        "SELECT id,source,sha256 FROM analyses WHERE source IS NOT NULL AND source_ref IS NULL"
    ):
        evidence = storage().put(row["source"])
        if evidence.sha256 != row["sha256"]:
            raise ValueError("Legacy evidence hash mismatch; migration stopped")
        storage().read(evidence.key, evidence.sha256)
        conn.execute(
            "UPDATE analyses SET source_ref=?,size=?,source=NULL WHERE id=?",
            (evidence.key, evidence.size, row["id"]),
        )

    for row in conn.execute(
        "SELECT id,result FROM analyses WHERE result IS NOT NULL AND result LIKE '%raw%'"
    ):
        document = json.loads(row["result"])
        changed = False
        for position, item in enumerate(document.get("eml", {}).get("attachments", [])):
            if "raw" not in item:
                continue
            raw = base64.b64decode(item.pop("raw"), validate=True)
            value = storage().put(raw)
            claimed = item.get("hash", {}).get("sha256")
            if claimed and claimed != value.sha256:
                raise ValueError("Legacy attachment hash mismatch; migration stopped")
            conn.execute(
                "INSERT OR REPLACE INTO evidence_attachments VALUES (?,?,?,?,?)",
                (row["id"], position, value.key, value.sha256, value.size),
            )
            changed = True
        if changed:
            conn.execute(
                "UPDATE analyses SET result=? WHERE id=?",
                (json.dumps(document), row["id"]),
            )
    conn.execute("""CREATE TRIGGER IF NOT EXISTS immutable_original
        BEFORE UPDATE OF source_ref,sha256,size,filename,ingestion_source,created_at ON analyses
        WHEN OLD.source_ref IS NOT NULL
        BEGIN SELECT RAISE(ABORT,'Original evidence is immutable'); END""")


def original(conn, analysis_id: str) -> bytes:
    row = conn.execute(
        "SELECT source_ref,source,sha256 FROM analyses WHERE id=?", (analysis_id,)
    ).fetchone()
    if not row:
        raise FileNotFoundError("Analysis missing")
    if row["source_ref"]:
        return storage().read(row["source_ref"], row["sha256"])
    if row["source"] is not None:
        return bytes(row["source"])
    raise FileNotFoundError("Evidence unavailable")
