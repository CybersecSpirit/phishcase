"""Bounded cryptographic worker. DNS is supplied by the authorized parent only."""

import asyncio
import base64
import json
import logging
import resource
import sys
from pathlib import Path

MAX_MESSAGE_BYTES = 20 * 1024 * 1024
MAX_SIGNATURES = 5


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    if sys.platform == "linux":
        memory = 384 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))


class DNSUnavailableError(Exception):
    def __init__(self, code):
        self.code = code


def emit(value):
    sys.stdout.write(json.dumps(value) + "\n")
    sys.stdout.flush()


async def parent_dns(name, **_kwargs):
    # No resolver or provider is instantiated inside the cryptographic process.
    emit({"dns": name.decode("ascii")})
    line = sys.stdin.buffer.readline(8193)
    if len(line) > 8192 or not line.endswith(b"\n"):
        raise DNSUnavailableError("verification_unavailable")
    message = json.loads(line)
    if message.get("error"):
        raise DNSUnavailableError(message["error"])
    return base64.b64decode(message["txt"], validate=True)


async def verify(raw):
    # Import crypto after resource limits, including parsing untrusted ASN.1 keys.
    import dkim
    from dkim.asyncsupport import DKIM

    logger = logging.Logger("phishcase.dkim.private", level=logging.CRITICAL)
    logger.addHandler(logging.NullHandler())
    verifier = DKIM(raw, logger=logger, timeout=2)
    signatures = [
        value for name, value in verifier.headers if name.lower() == b"dkim-signature"
    ]
    if not signatures:
        return {"verification": "unsigned", "reason_code": "no_signature"}
    if len(signatures) > MAX_SIGNATURES:
        return {"verification": "unavailable", "reason_code": "signature_limit"}
    valid, unavailable, malformed = False, None, False
    for index in range(len(signatures)):
        try:
            valid = await verifier.verify(idx=index, dnsfunc=parent_dns) or valid
        except DNSUnavailableError as exc:
            unavailable = exc.code
        except dkim.DKIMException, ValueError, UnicodeError, KeyError, TypeError:
            malformed = True
    if valid:
        return {"verification": "valid", "reason_code": "signature_verified"}
    if unavailable:
        return {"verification": "unavailable", "reason_code": unavailable}
    return {
        "verification": "invalid",
        "reason_code": "malformed_signature" if malformed else "signature_not_verified",
    }


if __name__ == "__main__":
    limits()
    source = Path(sys.argv[1])
    if source.stat().st_size > MAX_MESSAGE_BYTES:
        raise SystemExit(2)
    emit({"result": asyncio.run(verify(source.read_bytes()))})
