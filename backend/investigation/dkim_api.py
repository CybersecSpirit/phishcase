"""Explicit DKIM checks; parsing never invokes this DNS-capable service."""

import asyncio
import base64
import json
import os
import re
import signal
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Literal
from uuid import UUID

import aiodns
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict

from . import connectivity
from .auth import Writer
from .enrichment import EnrichmentResult, EnrichmentStatus, target
from .enrichment_api import analysis_record, decode, now, reserve
from .evidence import original
from .store import audit, db

router = APIRouter()
MAX_SIGNATURES = 5
MAX_DNS_BYTES = 4096
MAX_MESSAGE_BYTES = 20 * 1024 * 1024
VERIFICATION_TIMEOUT = 10
RECOVERY_DELAY = 60


class VerificationInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: Literal[True]
    request_id: UUID | None = None


class RecoveryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirm: Literal[True]


class VerificationUnavailableError(Exception):
    def __init__(self, code):
        self.code = code


async def resolve_txt(name):
    resolver = aiodns.DNSResolver(timeout=2, tries=1)
    try:
        records = await resolver.query(name, "TXT")
        if len(records) != 1:
            raise VerificationUnavailableError("dns_ambiguous_or_missing_key")
        value = records[0].text
        # c-ares may expose the individual DNS TXT character strings separately.
        if isinstance(value, list):
            value = b"".join(
                part.encode() if isinstance(part, str) else part for part in value
            )
        return value.encode() if isinstance(value, str) else value
    except aiodns.error.DNSError:
        raise VerificationUnavailableError("dns_unavailable") from None
    finally:
        resolver.cancel()


class BoundedDNS:
    def __init__(self, resolver=None):
        self.resolver = resolver
        self.queries = []
        self.domains = []
        self.cache = {}

    async def __call__(self, name, **_kwargs):
        name = name.decode("ascii").rstrip(".").lower()
        if (
            len(name) > 253
            or "._domainkey." not in name
            or not re.fullmatch(r"[a-z0-9_-]+(?:\.[a-z0-9_-]+)+", name)
            or any(len(label) > 63 for label in name.split("."))
        ):
            raise VerificationUnavailableError("invalid_dns_name")
        if name in self.cache:
            return self.cache[name]
        if len(self.queries) >= MAX_SIGNATURES:
            raise VerificationUnavailableError("dns_query_limit")
        self.queries.append(name)
        self.domains.append(name.split("._domainkey.", 1)[1])
        try:
            value = await asyncio.wait_for(
                (self.resolver or resolve_txt)(name), timeout=2
            )
        except TimeoutError:
            raise VerificationUnavailableError("dns_timeout") from None
        if not isinstance(value, bytes) or not value:
            raise VerificationUnavailableError("dns_no_key")
        if len(value) > MAX_DNS_BYTES:
            raise VerificationUnavailableError("dns_response_limit")
        self.cache[name] = value
        return value


def worker_command(source):
    return [sys.executable, "-m", "backend.investigation.dkim_task", str(source)]


def worker_environment():
    # Never inherit database, SMTP, billing, signing or provider secrets. This
    # minimal worker does not load application settings or instantiate DNS.
    runtime_keys = {
        "PATH",
        "LANG",
        "LC_ALL",
        "SYSTEMROOT",
        "VIRTUAL_ENV",
        "PYTHONPATH",
        "DYLD_LIBRARY_PATH",
        "LD_LIBRARY_PATH",
    }
    return {
        **{key: value for key, value in os.environ.items() if key in runtime_keys},
        "PHISHCASE_DISABLE_DOTENV": "true",
        "CONNECTIVITY_MODE": "offline",
        "PYTHONDONTWRITEBYTECODE": "1",
    }


async def exchange(process, dns):
    for _ in range(MAX_SIGNATURES + 1):
        line = await process.stdout.readline()
        if not line or len(line) > 8192:
            break
        message = json.loads(line)
        if "result" in message:
            result = message["result"]
            if result["verification"] not in {
                "valid",
                "invalid",
                "unsigned",
                "unavailable",
            }:
                break
            if not re.fullmatch(r"[a-z_]{1,64}", result["reason_code"]):
                break
            if await process.wait() == 0:
                return result
            break
        try:
            value = await dns(message["dns"].encode("ascii"))
            reply = {"txt": base64.b64encode(value).decode("ascii")}
        except VerificationUnavailableError as exc:
            reply = {"error": exc.code}
        process.stdin.write(json.dumps(reply).encode("ascii") + b"\n")
        await process.stdin.drain()
    return {"verification": "unavailable", "reason_code": "verification_resource_limit"}


async def crypto_worker(source, dns):
    process = await asyncio.create_subprocess_exec(
        *worker_command(source),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=worker_environment(),
        start_new_session=True,
        limit=8192,
    )
    try:
        async with asyncio.timeout(VERIFICATION_TIMEOUT):
            return await exchange(process, dns)
    except TimeoutError:
        return {"verification": "unavailable", "reason_code": "verification_timeout"}
    except ValueError, KeyError, TypeError, OSError:
        return {
            "verification": "unavailable",
            "reason_code": "verification_unavailable",
        }
    finally:
        if process.returncode is None:
            with suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        await process.wait()
        process.stdin.close()


async def verify_original(raw, resolver=None):
    """Isolated real cryptography, with DNS injected into the parent for tests."""
    dns = BoundedDNS(resolver)
    if len(raw) > MAX_MESSAGE_BYTES:
        result = {"verification": "unavailable", "reason_code": "message_size_limit"}
    else:
        with tempfile.TemporaryDirectory(prefix="phishcase-dkim-") as directory:
            source = Path(directory) / "original"
            source.write_bytes(raw)
            source.chmod(0o600)
            result = await crypto_worker(source, dns)
    return {
        **result,
        "signing_domains": list(dict.fromkeys(dns.domains)),
        "dns_queries": dns.queries,
    }


def persist_terminal(conn, row, result, user, case_id, action):
    conn.execute(
        "UPDATE enrichments SET status=?,result=?,updated_at=?,poll_after=0 WHERE id=? AND status='pending'",
        (result.status, json.dumps(result.public()), now(), row["id"]),
    )
    audit(conn, user["id"], action, case_id, result.metadata["verification"])
    return decode(
        conn.execute("SELECT * FROM enrichments WHERE id=?", (row["id"],)).fetchone()
    )


def complete_verification(identifier, result, user, case_id):
    # Same write transaction/tenant advisory lock as purge: terminal state and
    # audit must become visible together. A recovered operation is never revived.
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM enrichments WHERE id=?", (identifier,)
        ).fetchone()
        if not row:
            raise HTTPException(410, "Verification evidence is no longer available")
        if row["status"] != "pending":
            return decode(row)
        return persist_terminal(
            conn, row, result, user, case_id, "authentication.dkim_checked"
        )


@router.post("/analyses/{analysis_id}/dkim/{enrichment_id}/recover")
def recover_dkim(
    analysis_id: str, enrichment_id: str, data: RecoveryInput, user: Writer
):
    # This explicitly closes an interrupted local operation. It needs neither
    # egress permission nor a DNS request and never starts another verification.
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        analysis = analysis_record(conn, analysis_id)
        row = conn.execute(
            "SELECT * FROM enrichments WHERE id=? AND analysis_id=? AND provider='dkim' AND action='verify'",
            (enrichment_id, analysis_id),
        ).fetchone()
        if not row:
            raise HTTPException(404, "DKIM verification not found")
        if row["status"] != "pending":
            return decode(row)
        if row["poll_after"] > time.time():
            raise HTTPException(
                409, "DKIM verification is still active; recovery is not available yet"
            )
        result = EnrichmentResult(
            "dkim",
            target("sha256", row["value"]),
            EnrichmentStatus.UNAVAILABLE,
            summary="Interrupted DKIM verification closed without a DNS request. A new check requires an explicit action.",
            metadata={
                "verification": "unavailable",
                "reason_code": "verification_interrupted",
                "source_sha256": row["value"],
                "signing_domains": [],
                "dns_queries": [],
            },
        )
        return persist_terminal(
            conn,
            row,
            result,
            user,
            analysis["case_id"],
            "authentication.dkim_recovered",
        )


@router.post("/analyses/{analysis_id}/dkim")
async def verify_dkim(analysis_id: str, data: VerificationInput, user: Writer):
    if not connectivity.dkim_allowed():
        raise HTTPException(403, "DKIM verification disabled by connectivity policy")
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        analysis = analysis_record(conn, analysis_id)
        try:
            raw = original(conn, analysis_id)
        except OSError, ValueError:
            raise HTTPException(
                409, "Original evidence unavailable or modified"
            ) from None
        selected = target("sha256", analysis["sha256"])
        row, duplicate = reserve(
            conn,
            analysis,
            user,
            "dkim",
            selected,
            "verify",
            str(data.request_id) if data.request_id else None,
        )
        if duplicate:
            return decode(row)
        pending = conn.execute(
            "SELECT id FROM enrichments WHERE analysis_id=? AND provider='dkim' AND action='verify' AND status='pending' AND id<>?",
            (analysis_id, row["id"]),
        ).fetchone()
        if pending:
            # Raising inside the write transaction rolls back the new reserve
            # and its rate slot. Existing request IDs still replay their result.
            raise HTTPException(
                409,
                "A DKIM verification is pending; recover it explicitly if interrupted",
            )
        active = EnrichmentResult(
            "dkim",
            selected,
            EnrichmentStatus.PENDING,
            summary="DKIM verification is active. An interrupted check may be closed explicitly after its recovery deadline.",
            metadata={
                "verification": "unavailable",
                "reason_code": "verification_in_progress",
                "source_sha256": analysis["sha256"],
                "signing_domains": [],
                "dns_queries": [],
            },
        )
        conn.execute(
            "UPDATE enrichments SET result=?,poll_after=? WHERE id=?",
            (json.dumps(active.public()), time.time() + RECOVERY_DELAY, row["id"]),
        )
    if analysis["filename"].lower().endswith(".msg"):
        result = {
            "verification": "unavailable",
            "reason_code": "original_format_unsupported",
            "signing_domains": [],
            "dns_queries": [],
        }
    else:
        try:
            result = await verify_original(raw)
        except Exception:
            result = {
                "verification": "unavailable",
                "reason_code": "verification_unavailable",
                "signing_domains": [],
                "dns_queries": [],
            }
    result["source_sha256"] = analysis["sha256"]
    status = (
        EnrichmentStatus.UNAVAILABLE
        if result["verification"] == "unavailable"
        else EnrichmentStatus.AVAILABLE
    )
    return complete_verification(
        row["id"],
        EnrichmentResult(
            "dkim",
            selected,
            status,
            unknown=1,
            summary="DKIM: "
            + result["verification"]
            + ". A signature result is not a phishing verdict.",
            metadata=result,
        ),
        user,
        analysis["case_id"],
    )
