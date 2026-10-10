"""Provider contract adapted from draft PR #1; consultation never implies submission."""

import ipaddress
import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit

from . import connectivity


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
    PENDING = "pending"


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
    # Kept for the PR #1 Python contract, never exposed or persisted by the API.
    raw: dict = field(default_factory=dict, repr=False)
    unknown: int | None = None
    first_seen: str | None = None
    file_type: str | None = None
    metadata: dict = field(default_factory=dict)

    def public(self):
        value = asdict(self)
        value.pop("raw")
        return value


@dataclass(frozen=True, slots=True)
class EnrichmentPolicy:
    online: bool = False
    external_lookups: bool = False
    file_submission: bool = False
    url_submission: bool = False

    def allows_lookup(self):
        return self.online and self.external_lookups

    def allows_submission(self, kind):
        return self.online and (
            (kind == TargetKind.FILE and self.file_submission)
            or (kind == TargetKind.URL and self.url_submission)
        )

    @classmethod
    def configured(cls, provider):
        return cls(
            online=connectivity.mode() != "offline",
            external_lookups=connectivity.provider_lookups_allowed(provider),
            file_submission=connectivity.submission_allowed(provider, "file"),
            url_submission=connectivity.submission_allowed(provider, "url"),
        )


class EnrichmentProvider(Protocol):
    name: str

    async def lookup(self, target: EnrichmentTarget) -> EnrichmentResult: ...
    async def submit(
        self, target: EnrichmentTarget, *, content=None, visibility="private"
    ) -> EnrichmentResult: ...
    async def poll(
        self, target: EnrichmentTarget, external_id: str
    ) -> EnrichmentResult: ...
    def normalize(self, target: EnrichmentTarget, data: dict) -> EnrichmentResult: ...
    async def healthcheck(self) -> dict: ...


class EnrichmentDisabled(RuntimeError):  # noqa: N818 - public PR #1 contract
    pass


class ProviderError(RuntimeError):
    """Only a finite, non-sensitive error code crosses the transport boundary."""

    def __init__(self, code="provider_error"):
        self.code = code
        super().__init__(code)


async def lookup(provider, target, policy):
    if not policy.allows_lookup():
        raise EnrichmentDisabled("External lookups disabled")
    return await provider.lookup(target)


async def submit(provider, target, policy, *, content=None, visibility=None):
    if not policy.allows_submission(target.kind):
        raise EnrichmentDisabled("External submissions disabled")
    if target.kind == TargetKind.FILE and content is None:
        raise ValueError("File submission requires content")
    options = {"content": content}
    if visibility is not None:
        options["visibility"] = visibility
    return await provider.submit(target, **options)


async def poll(provider, target, external_id, policy):
    if not policy.allows_lookup():
        raise EnrichmentDisabled("External polling disabled")
    return await provider.poll(target, external_id)


async def healthcheck(provider, policy):
    if not policy.allows_lookup():
        raise EnrichmentDisabled("External healthcheck disabled")
    return await provider.healthcheck()


def target(kind, value):
    """Validate IOC syntax without resolving or visiting it."""
    kind = TargetKind(kind)
    if (
        not isinstance(value, str)
        or len(value) > 2048
        or any(ord(c) < 32 for c in value)
    ):
        raise ValueError("Invalid target")
    if kind in {TargetKind.SHA256, TargetKind.FILE}:
        value = value.lower()
        if not re.fullmatch(r"[a-f0-9]{64}", value):
            raise ValueError("Invalid SHA256")
    elif kind == TargetKind.IP:
        value = str(ipaddress.ip_address(value))
    elif kind == TargetKind.DOMAIN:
        value = value.lower().rstrip(".")
        if len(value) > 253 or not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
            value,
        ):
            raise ValueError("Invalid domain")
    elif kind == TargetKind.URL:
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username
            or parsed.password
        ):
            raise ValueError("Invalid HTTP URL")
        _ = parsed.port
    else:
        raise ValueError("Unsupported target kind")
    return EnrichmentTarget(kind, value)
