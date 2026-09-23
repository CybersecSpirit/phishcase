"""Provider-neutral enrichment contracts for PhishCase.

External enrichment is deliberately opt-in. Providers must never be called when
the instance is offline or when the administrator disabled external lookups.
File submission is a separate capability from hash/IOC lookup so that a lookup
can never silently turn into a file upload.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol


class TargetKind(StrEnum):
    SHA256 = "sha256"
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    FILE = "file"


class EnrichmentStatus(StrEnum):
    AVAILABLE = "available"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class EnrichmentTarget:
    kind: TargetKind
    value: str


@dataclass(frozen=True, slots=True)
class EnrichmentResult:
    provider: str
    target: EnrichmentTarget
    status: EnrichmentStatus
    malicious: int | None = None
    suspicious: int | None = None
    harmless: int | None = None
    summary: str = ""
    external_id: str | None = None
    external_url: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EnrichmentPolicy:
    online: bool = False
    external_lookups: bool = False
    file_submission: bool = False
    url_submission: bool = False

    def allows_lookup(self) -> bool:
        return self.online and self.external_lookups

    def allows_submission(self, kind: TargetKind) -> bool:
        if not self.online:
            return False
        if kind is TargetKind.FILE:
            return self.file_submission
        if kind is TargetKind.URL:
            return self.url_submission
        return False


class EnrichmentProvider(Protocol):
    """Common contract implemented by VirusTotal, urlscan and future providers."""

    name: str

    async def lookup(self, target: EnrichmentTarget) -> EnrichmentResult:
        """Look up an existing indicator without submitting its underlying content."""
        ...

    async def submit(
        self, target: EnrichmentTarget, *, content: bytes | None = None
    ) -> EnrichmentResult:
        """Explicitly submit content/URL when policy and provider licensing allow it."""
        ...


class EnrichmentDisabled(RuntimeError):
    pass


async def lookup(
    provider: EnrichmentProvider,
    target: EnrichmentTarget,
    policy: EnrichmentPolicy,
) -> EnrichmentResult:
    if not policy.allows_lookup():
        raise EnrichmentDisabled("External enrichment is disabled or the instance is offline")
    return await provider.lookup(target)


async def submit(
    provider: EnrichmentProvider,
    target: EnrichmentTarget,
    policy: EnrichmentPolicy,
    *,
    content: bytes | None = None,
) -> EnrichmentResult:
    if not policy.allows_submission(target.kind):
        raise EnrichmentDisabled("External submission is disabled by policy")
    if target.kind is TargetKind.FILE and content is None:
        raise ValueError("File submission requires content")
    return await provider.submit(target, content=content)
