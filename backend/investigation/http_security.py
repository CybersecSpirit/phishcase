"""Bound incoming bodies before parser dispatch, and safe response defaults."""

import json
import os
import time
from uuid import uuid4

from loguru import logger


class RequestTooLargeError(Exception):
    pass


class SecurityMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):  # noqa: C901 - ASGI wrappers share request state
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        maximum = 21 * 1024 * 1024
        headers = dict(scope.get("headers", []))
        try:
            declared = int(headers.get(b"content-length", b"0"))
        except ValueError:
            declared = maximum + 1
        request_id = uuid4().hex
        start_time = time.monotonic()
        received = 0
        started = False

        async def guarded_receive():
            nonlocal received
            message = await receive()
            received += len(message.get("body", b""))
            if received > maximum:
                raise RequestTooLargeError()
            return message

        async def guarded_send(message):
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
                items = list(message.get("headers", []))
                items.extend(
                    [
                        (b"x-content-type-options", b"nosniff"),
                        (b"referrer-policy", b"no-referrer"),
                        (
                            b"permissions-policy",
                            b"camera=(), microphone=(), geolocation=()",
                        ),
                        (b"x-request-id", request_id.encode()),
                    ]
                )
                if scope["path"].startswith("/api"):
                    items.append((b"cache-control", b"no-store"))
                if os.environ.get("ENVIRONMENT") == "production":
                    items.append((b"strict-transport-security", b"max-age=31536000"))
                message["headers"] = items
                route = getattr(scope.get("route"), "path", "<unmatched>")
                logger.bind(
                    request_id=request_id,
                    method=scope["method"],
                    route=route,
                    status=message["status"],
                    duration_ms=round((time.monotonic() - start_time) * 1000),
                ).info("http.request")
            await send(message)

        async def reject():
            body = json.dumps(
                {"detail": "Request body exceeds 21 MiB", "code": "body_too_large"}
            ).encode()
            await guarded_send(
                {
                    "type": "http.response.start",
                    "status": 413,
                    "headers": [(b"content-type", b"application/json")],
                }
            )
            await send({"type": "http.response.body", "body": body})

        if declared > maximum:
            return await reject()
        try:
            await self.app(scope, guarded_receive, guarded_send)
        except RequestTooLargeError:
            if not started:
                await reject()
