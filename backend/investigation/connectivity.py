"""Administrative egress policy, fail closed by default."""

import os
from contextvars import ContextVar

policy_factory: ContextVar = ContextVar("phishcase_connectivity_policy", default=None)


def mode() -> str:
    factory = policy_factory.get()
    value = (
        factory().get("mode", "offline")
        if factory is not None
        else os.environ.get("CONNECTIVITY_MODE", "offline")
    ).lower()
    return value if value in {"offline", "restricted", "connected"} else "offline"


def lookups_allowed() -> bool:
    return mode() in {"restricted", "connected"}


def provider_lookups_allowed(provider: str) -> bool:
    factory = policy_factory.get()
    enabled = (
        factory().get("lookups", {}).get(provider, False)
        if factory is not None
        else os.environ.get(f"{provider.upper()}_LOOKUP_ENABLED", "true").lower()
        == "true"
    )
    return lookups_allowed() and bool(enabled)


def submission_allowed(provider: str, kind: str) -> bool:
    factory = policy_factory.get()
    if factory is not None:
        return mode() == "connected" and bool(
            factory().get("submissions", {}).get(provider, {}).get(kind, False)
        )
    return (
        mode() == "connected"
        and os.environ.get(
            f"{provider.upper()}_ALLOW_{kind.upper()}_SUBMISSION", "false"
        ).lower()
        == "true"
    )
