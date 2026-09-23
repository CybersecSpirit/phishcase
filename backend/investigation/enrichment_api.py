"""Explicit, audited enrichments of immutable analysis evidence in Community."""

import base64
import hashlib
import json
import time
from datetime import UTC, datetime
from typing import Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from . import connectivity
from .auth import Admin, User, Writer
from .enrichment import (
    EnrichmentDisabled,
    EnrichmentPolicy,
    EnrichmentResult,
    EnrichmentStatus,
    ProviderError,
    healthcheck,
    lookup,
    poll,
    submit,
    target,
)
from .evidence import storage
from .processing import extract_iocs
from .providers import PROVIDERS, configured, credentials_factory, get_provider
from .providers.http import MAX_SUBMISSION_BYTES
from .store import audit, db

router = APIRouter()
ProviderName = Literal["virustotal", "urlscan"]


def initialize_enrichments(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS enrichments (
        id TEXT PRIMARY KEY, analysis_id TEXT NOT NULL REFERENCES analyses(id),
        provider TEXT NOT NULL, action TEXT NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL,
        status TEXT NOT NULL, result TEXT NOT NULL, external_id TEXT,
        created_by INTEGER NOT NULL REFERENCES users(id),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL, poll_after REAL NOT NULL DEFAULT 0,
        request_id TEXT UNIQUE, request_fingerprint TEXT NOT NULL, polls INTEGER NOT NULL DEFAULT 0)""")
    conn.execute(
        "CREATE INDEX IF NOT EXISTS enrichment_analysis ON enrichments(analysis_id,created_at DESC)"
    )
    conn.execute("""CREATE TABLE IF NOT EXISTS enrichment_attempts (
        provider TEXT NOT NULL, requested_at REAL NOT NULL)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS integration_health (
        provider TEXT PRIMARY KEY, result TEXT NOT NULL, checked_at TEXT NOT NULL)""")


def now():
    return datetime.now(UTC).isoformat()


def capabilities(user):
    entries = []
    for name, provider in PROVIDERS.items():
        policy = EnrichmentPolicy.configured(name)
        ready = configured(name)
        writer = user["role"] in {"admin", "analyst"}
        entry = {
            "name": name,
            "configured": ready,
            "lookup_allowed": ready and writer and policy.allows_lookup(),
            "lookup_kinds": provider.lookup_kinds,
            "submission_allowed": {
                kind: ready
                and writer
                and kind in provider.submission_kinds
                and policy.allows_submission(kind)
                for kind in ("file", "url")
            },
            "health": "configured" if ready else "unconfigured",
            "secret_source": "tenant"
            if credentials_factory.get() is not None
            else "environment",
        }
        if name == "urlscan":
            entry["visibility_default"] = "private"
        with db() as conn:
            row = conn.execute(
                "SELECT result,checked_at FROM integration_health WHERE provider=?",
                (name,),
            ).fetchone()
        if row:
            entry["last_healthcheck"] = {
                **json.loads(row["result"]),
                "checked_at": row["checked_at"],
            }
        entries.append(entry)
    return {
        "mode": connectivity.mode(),
        "providers": entries,
        "dkim": {
            "enabled": connectivity.dkim_enabled(),
            "allowed": connectivity.dkim_allowed()
            and user["role"] in {"admin", "analyst"},
            "mode": connectivity.mode(),
        },
    }


@router.get("/integrations")
def integrations(user: User):
    return capabilities(user)


def policy_for(provider, operation, kind=None):
    policy = EnrichmentPolicy.configured(provider)
    allowed = (
        policy.allows_submission(kind)
        if operation == "submit"
        else policy.allows_lookup()
    )
    if not allowed:
        raise HTTPException(403, "External action disabled by connectivity policy")
    if not configured(provider):
        raise HTTPException(409, "Provider key is not configured")
    return policy


def reserve_rate(conn, provider):
    # Shared quota per provider, including failures/healthchecks, bounded across users/workers.
    clock = time.time()
    conn.execute(
        "DELETE FROM enrichment_attempts WHERE requested_at<?", (clock - 3600,)
    )
    limit = 4 if provider == "virustotal" else 10
    used = conn.execute(
        "SELECT count(*) FROM enrichment_attempts WHERE provider=? AND requested_at>?",
        (provider, clock - 60),
    ).fetchone()[0]
    if used >= limit:
        raise HTTPException(
            429,
            "Local provider rate limit; retry after one minute",
            headers={"Retry-After": "60"},
        )
    conn.execute("INSERT INTO enrichment_attempts VALUES (?,?)", (provider, clock))


@router.post("/integrations/{provider}/health")
async def integration_health(provider: ProviderName, user: Admin):
    policy = policy_for(provider, "lookup")
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        reserve_rate(conn, provider)
        audit(conn, user["id"], "integration.healthcheck", detail=provider)
    try:
        result = await healthcheck(get_provider(provider), policy)
    except ProviderError as error:
        result = {"status": "error", "detail": error.code}
    except Exception:
        result = {"status": "error", "detail": "provider_error"}
    checked_at = now()
    with db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO integration_health VALUES (?,?,?)",
            (provider, json.dumps(result), checked_at),
        )
    return {"provider": provider, **result, "checked_at": checked_at}


def analysis_record(conn, analysis_id):
    row = conn.execute(
        "SELECT a.* FROM analyses a JOIN cases c ON c.id=a.case_id WHERE a.id=?",
        (analysis_id,),
    ).fetchone()
    if not row:
        raise HTTPException(404, "Analysis not found")
    return row


def decode(row):
    return {
        **json.loads(row["result"]),
        "id": row["id"],
        "analysis_id": row["analysis_id"],
        "action": row["action"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "poll_after": row["poll_after"],
    }


@router.get("/analyses/{analysis_id}/enrichments")
def list_enrichments(
    analysis_id: str,
    user: User,
    latest: bool = False,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    with db() as conn:
        analysis_record(conn, analysis_id)
        source = "enrichments"
        where = "analysis_id=?"
        if latest:
            source = "(SELECT *, ROW_NUMBER() OVER (PARTITION BY analysis_id,provider,kind,value ORDER BY created_at DESC,id DESC) AS rank FROM enrichments)"
            where += " AND rank=1"
        total = conn.execute(
            f"SELECT count(*) FROM {source} WHERE {where}", (analysis_id,)
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM {source} WHERE {where} ORDER BY created_at DESC,id DESC LIMIT ? OFFSET ?",
            (analysis_id, limit, offset),
        ).fetchall()
    return {"items": [decode(row) for row in rows], "total": total}


class LookupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: ProviderName
    kind: Literal["sha256", "url", "domain", "ip"]
    value: str = Field(min_length=1, max_length=2048)


class SubmissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: ProviderName
    kind: Literal["file", "url"]
    value: str | None = Field(None, max_length=2048)
    attachment_index: int | None = Field(None, ge=0)
    confirm: Literal[True]
    visibility: Literal["private", "unlisted", "public"] = "private"
    request_id: UUID | None = None


def linked_target(conn, analysis, kind, value):
    try:
        selected = target(kind, value)
    except ValueError, TypeError:
        raise HTTPException(422, "Invalid target") from None
    document = json.loads(analysis["result"] or "{}")
    candidates = set(extract_iocs(document))
    candidates.add(("sha256", analysis["sha256"]))
    # Only evidence-derived IOCs are eligible; analyst-added case IOCs don't grant egress.
    for found_kind, found_value in candidates:
        if found_kind != kind:
            continue
        try:
            if target(kind, found_value) == selected:
                return selected
        except ValueError, TypeError:
            continue
    raise HTTPException(422, "Target is not present in this analysis")


def attachment_target(conn, analysis, index):
    attachments = (
        json.loads(analysis["result"] or "{}").get("eml", {}).get("attachments", [])
    )
    if index is None or index >= len(attachments):
        raise HTTPException(422, "Select an attachment from this analysis")
    item = attachments[index]
    stored = conn.execute(
        "SELECT * FROM evidence_attachments WHERE analysis_id=? AND position=?",
        (analysis["id"], index),
    ).fetchone()
    try:
        digest = item.get("hash", {}).get("sha256")
        if stored:
            if stored["size"] > MAX_SUBMISSION_BYTES:
                raise HTTPException(413, "Attachment exceeds 20 MiB")
            content = storage().read(stored["storage_key"], stored["sha256"])
            if digest != stored["sha256"]:
                raise ValueError()
        else:
            raw = item.get("raw", "")
            if len(raw) > (MAX_SUBMISSION_BYTES * 4 // 3 + 8):
                raise HTTPException(413, "Attachment exceeds 20 MiB")
            content = base64.b64decode(raw, validate=True)
        if len(content) > MAX_SUBMISSION_BYTES:
            raise HTTPException(413, "Attachment exceeds 20 MiB")
        if not digest or hashlib.sha256(content).hexdigest() != digest:
            raise ValueError()
        return target("file", digest), content
    except OSError, ValueError, TypeError:
        raise HTTPException(
            409, "Attachment evidence unavailable or integrity check failed"
        ) from None


def reserve(
    conn, analysis, user, provider, selected, action, request_id=None, visibility=None
):
    fingerprint = json.dumps(
        [
            analysis["id"],
            user["id"],
            provider,
            action,
            selected.kind,
            selected.value,
            visibility,
        ]
    )
    if request_id:
        previous = conn.execute(
            "SELECT * FROM enrichments WHERE request_id=?", (request_id,)
        ).fetchone()
        if previous:
            if previous["request_fingerprint"] != fingerprint:
                raise HTTPException(
                    409, "Idempotency key already used for a different action"
                )
            return previous, True
    if action == "submit":
        pending = conn.execute(
            "SELECT id FROM enrichments WHERE analysis_id=? AND provider=? AND kind=? AND value=? AND action='submit' AND status='pending'",
            (analysis["id"], provider, selected.kind, selected.value),
        ).fetchone()
        if pending:
            raise HTTPException(
                409, "A submission for this evidence is already pending"
            )
    if (
        conn.execute(
            "SELECT count(*) FROM enrichments WHERE analysis_id=?", (analysis["id"],)
        ).fetchone()[0]
        >= 1000
    ):
        raise HTTPException(409, "Analysis enrichment history limit reached")
    reserve_rate(conn, provider)
    identifier = str(uuid4())
    timestamp = now()
    initial = EnrichmentResult(
        provider,
        selected,
        EnrichmentStatus.PENDING,
        summary="Request in progress; do not repeat submission.",
        metadata={"requested_visibility": visibility}
        if provider == "urlscan" and action == "submit"
        else {},
    )
    conn.execute(
        """INSERT INTO enrichments (id,analysis_id,provider,action,kind,value,status,result,created_by,created_at,updated_at,request_id,request_fingerprint,poll_after)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            identifier,
            analysis["id"],
            provider,
            action,
            selected.kind,
            selected.value,
            initial.status,
            json.dumps(initial.public()),
            user["id"],
            timestamp,
            timestamp,
            request_id,
            fingerprint,
            time.time() + 30,
        ),
    )
    audit(
        conn,
        user["id"],
        f"enrichment.{action}",
        analysis["case_id"],
        json.dumps(
            {
                "id": identifier,
                "provider": provider,
                "kind": selected.kind,
                "visibility": visibility,
            }
        ),
    )
    return conn.execute(
        "SELECT * FROM enrichments WHERE id=?", (identifier,)
    ).fetchone(), False


def save_result(identifier, result):
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM enrichments WHERE id=?", (identifier,)
        ).fetchone()
        previous = json.loads(row["result"])
        public = result.public()
        public["external_id"] = public.get("external_id") or row["external_id"]
        public["external_url"] = public.get("external_url") or previous.get(
            "external_url"
        )
        public["metadata"] = {
            **previous.get("metadata", {}),
            **public.get("metadata", {}),
        }
        requested_visibility = public["metadata"].get("requested_visibility")
        actual_visibility = public["metadata"].get("visibility")
        if (
            requested_visibility
            and actual_visibility
            and requested_visibility != actual_visibility
        ):
            public["status"] = "error"
            public["summary"] = (
                "Provider visibility differs from the requested visibility; check the provider."
            )
            public["metadata"]["error_code"] = "visibility_mismatch"
        conn.execute(
            "UPDATE enrichments SET status=?,result=?,external_id=?,updated_at=?,poll_after=? WHERE id=?",
            (
                public["status"],
                json.dumps(public),
                public["external_id"],
                now(),
                time.time() + 30 if public["status"] == "pending" else 0,
                identifier,
            ),
        )
        return decode(
            conn.execute(
                "SELECT * FROM enrichments WHERE id=?", (identifier,)
            ).fetchone()
        )


async def execute(identifier, provider, selected, operation):
    try:
        result = await operation
    except EnrichmentDisabled:
        result = EnrichmentResult(
            provider,
            selected,
            EnrichmentStatus.ERROR,
            summary="Action disabled by connectivity policy.",
            metadata={"error_code": "policy_disabled"},
        )
    except Exception as error:
        code = error.code if isinstance(error, ProviderError) else "provider_error"
        result = EnrichmentResult(
            provider,
            selected,
            EnrichmentStatus.ERROR,
            summary="Provider request failed. A failed submission may have been accepted; verify with provider before resubmitting.",
            metadata={"error_code": code},
        )
    return save_result(identifier, result)


@router.post("/analyses/{analysis_id}/enrichments/lookup")
async def lookup_analysis(analysis_id: str, payload: LookupRequest, user: Writer):
    policy = policy_for(payload.provider, "lookup")
    if payload.kind not in PROVIDERS[payload.provider].lookup_kinds:
        raise HTTPException(422, "Provider does not support this target kind")
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        analysis = analysis_record(conn, analysis_id)
        selected = linked_target(conn, analysis, payload.kind, payload.value)
        row, _ = reserve(conn, analysis, user, payload.provider, selected, "lookup")
    return await execute(
        row["id"],
        payload.provider,
        selected,
        lookup(get_provider(payload.provider), selected, policy),
    )


@router.post("/analyses/{analysis_id}/enrichments/submit")
async def submit_analysis(analysis_id: str, payload: SubmissionRequest, user: Writer):
    policy = policy_for(payload.provider, "submit", payload.kind)
    if payload.kind not in PROVIDERS[payload.provider].submission_kinds:
        raise HTTPException(422, "Provider does not support this submission kind")
    if (payload.kind == "file" and payload.value is not None) or (
        payload.kind == "url"
        and (not payload.value or payload.attachment_index is not None)
    ):
        raise HTTPException(
            422, "Select exactly one stored attachment or extracted URL"
        )
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        analysis = analysis_record(conn, analysis_id)
        if payload.kind == "file":
            selected, content = attachment_target(
                conn, analysis, payload.attachment_index
            )
        else:
            selected, content = (
                linked_target(conn, analysis, "url", payload.value),
                None,
            )
        row, reused = reserve(
            conn,
            analysis,
            user,
            payload.provider,
            selected,
            "submit",
            str(payload.request_id) if payload.request_id else None,
            payload.visibility,
        )
    if reused:
        return decode(row)
    return await execute(
        row["id"],
        payload.provider,
        selected,
        submit(
            get_provider(payload.provider),
            selected,
            policy,
            content=content,
            visibility=payload.visibility,
        ),
    )


@router.post("/analyses/{analysis_id}/enrichments/{enrichment_id}/poll")
async def poll_analysis(analysis_id: str, enrichment_id: str, user: Writer):
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        analysis = analysis_record(conn, analysis_id)
        row = conn.execute(
            "SELECT * FROM enrichments WHERE id=? AND analysis_id=?",
            (enrichment_id, analysis_id),
        ).fetchone()
        if not row:
            raise HTTPException(404, "Enrichment not found")
        policy = policy_for(row["provider"], "lookup")
        if not row["external_id"] or row["status"] not in {"pending", "error"}:
            raise HTTPException(409, "No pending provider job to poll")
        if row["poll_after"] > time.time():
            raise HTTPException(
                429, "Wait before polling again", headers={"Retry-After": "30"}
            )
        if row["polls"] >= 40:
            raise HTTPException(
                409, "Polling limit reached; inspect the provider report"
            )
        reserve_rate(conn, row["provider"])
        conn.execute(
            "UPDATE enrichments SET poll_after=?,polls=polls+1 WHERE id=?",
            (time.time() + 30, enrichment_id),
        )
        audit(conn, user["id"], "enrichment.poll", analysis["case_id"], enrichment_id)
    selected = target(row["kind"], row["value"])
    return await execute(
        enrichment_id,
        row["provider"],
        selected,
        poll(get_provider(row["provider"]), selected, row["external_id"], policy),
    )
