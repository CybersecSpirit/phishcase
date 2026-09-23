"""Short-lived parser process; never serve HTTP from this module."""

import asyncio
import json
import os
import resource
import sys
from pathlib import Path


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    if sys.platform == "linux":
        memory = int(os.environ.get("PARSER_MEMORY_MB", "768")) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))


async def analyze(raw):
    from backend.api.endpoints.analyze import _analyze
    from backend.dependencies import get_spam_assassin
    from backend.investigation.assessment import summarize
    from backend.investigation.connectivity import policy_factory
    from backend.investigation.processing import expected_engines

    # Parsing never performs provider lookups or DNS verification. The explicit
    # enrichment API owns policy, budgets, evidence selection and audit trails.
    local_policy = policy_factory.set(
        lambda: {"mode": "offline", "lookups": {}, "submissions": {}}
    )
    try:
        result = await _analyze(
            raw,
            optional_spam_assassin=get_spam_assassin(),
            optional_email_rep=None,
            optional_vt=None,
            optional_urlscan=None,
        )
        document = result.model_dump(mode="json", by_alias=False)
        document["assessment"] = summarize(
            document, expected=expected_engines(document, None, None, None)
        )
        return document
    finally:
        policy_factory.reset(local_policy)


if __name__ == "__main__":
    limits()
    raw = Path(sys.argv[1]).read_bytes()
    if len(raw) > 20 * 1024 * 1024:
        raise SystemExit(2)
    Path(sys.argv[2]).write_text(json.dumps(asyncio.run(analyze(raw))))
