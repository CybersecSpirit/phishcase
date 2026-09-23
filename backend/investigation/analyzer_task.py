"""Short-lived parser process; never serve HTTP from this module."""

import asyncio
import json
import os
import resource
import sys
from contextlib import AsyncExitStack
from pathlib import Path


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024, 64 * 1024 * 1024))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    if sys.platform == "linux":
        memory = int(os.environ.get("PARSER_MEMORY_MB", "768")) * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))


async def analyze(raw):
    from backend import clients, settings
    from backend.api.endpoints.analyze import _analyze
    from backend.dependencies import get_spam_assassin
    from backend.investigation.assessment import summarize
    from backend.investigation.connectivity import lookups_allowed
    from backend.investigation.processing import expected_engines

    async with AsyncExitStack() as stack:
        vt = urlscan = emailrep = None
        if lookups_allowed():
            if settings.VIRUSTOTAL_API_KEY:
                vt = await stack.enter_async_context(
                    clients.VirusTotal(apikey=str(settings.VIRUSTOTAL_API_KEY))
                )
            if settings.URLSCAN_API_KEY:
                urlscan = await stack.enter_async_context(
                    clients.UrlScan(api_key=settings.URLSCAN_API_KEY)
                )
            if settings.EMAIL_REP_API_KEY:
                emailrep = await stack.enter_async_context(
                    clients.EmailRep(api_key=settings.EMAIL_REP_API_KEY)
                )
        result = await _analyze(
            raw,
            optional_spam_assassin=get_spam_assassin(),
            optional_email_rep=emailrep,
            optional_vt=vt,
            optional_urlscan=urlscan,
        )
        document = result.model_dump(mode="json", by_alias=False)
        document["assessment"] = summarize(
            document, expected=expected_engines(document, emailrep, vt, urlscan)
        )
        return document


if __name__ == "__main__":
    limits()
    raw = Path(sys.argv[1]).read_bytes()
    if len(raw) > 20 * 1024 * 1024:
        raise SystemExit(2)
    Path(sys.argv[2]).write_text(json.dumps(asyncio.run(analyze(raw))))
