"""Bounded HTTP transport: no redirects, environment proxies, retries or raw errors."""

import asyncio
import json

import httpx

from ..enrichment import ProviderError

MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_SUBMISSION_BYTES = 20 * 1024 * 1024


class ProviderHTTP:
    origin: str
    key_header: str

    def __init__(
        self,
        api_key,
        *,
        transport=None,
        timeout=15,
        max_response_bytes=MAX_RESPONSE_BYTES,
    ):
        self._api_key = api_key
        self._transport = transport
        self.timeout = min(max(timeout, 0.01), 30)
        self.max_response_bytes = min(max_response_bytes, MAX_RESPONSE_BYTES)

    async def request(self, method, path, **kwargs):
        # Paths come only from adapters, which validate all interpolated IDs.
        if not path.startswith("/") or path.startswith("//") or "://" in path:
            raise ProviderError("invalid_endpoint")
        try:
            async with asyncio.timeout(self.timeout):
                async with httpx.AsyncClient(
                    transport=self._transport,
                    timeout=self.timeout,
                    follow_redirects=False,
                    trust_env=False,
                    headers={
                        self.key_header: self._api_key,
                        "User-Agent": "PhishCase-Community/1",
                        "Accept": "application/json",
                    },
                ) as client:
                    async with client.stream(
                        method, self.origin + path, **kwargs
                    ) as response:
                        return await self.decode(response)
        except TimeoutError, httpx.TimeoutException:
            raise ProviderError("timeout") from None
        except httpx.HTTPError:
            raise ProviderError("network_error") from None
        except ValueError, UnicodeError, RecursionError:
            raise ProviderError("invalid_response") from None

    async def decode(self, response):
        if response.status_code in {404, 410}:
            return response.status_code, {}
        if response.status_code == 429:
            raise ProviderError("rate_limited")
        if response.status_code in {401, 403}:
            raise ProviderError("credentials_or_plan_rejected")
        if not 200 <= response.status_code < 300:
            raise ProviderError("request_rejected")
        content = bytearray()
        async for chunk in response.aiter_bytes():
            if len(content) + len(chunk) > self.max_response_bytes:
                raise ProviderError("response_too_large")
            content.extend(chunk)
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ProviderError("invalid_response")
        return response.status_code, data


def count(value):
    return value if type(value) is int and 0 <= value <= 1_000_000 else None


def text(value, limit=300):
    return (
        "".join(c for c in value if c.isprintable())[:limit]
        if isinstance(value, str)
        else None
    )


def mapping(value):
    return value if isinstance(value, dict) else {}


def strings(value, limit=20):
    return (
        [text(v) for v in value[:limit] if isinstance(v, str)]
        if isinstance(value, list)
        else []
    )
