"""Bounded HTTP transport: no redirects, environment proxies, retries or raw errors."""

import asyncio
import json
import zlib

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
        self.max_response_bytes = max(1, min(max_response_bytes, MAX_RESPONSE_BYTES))

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
                        "Accept-Encoding": "identity",
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
        except ValueError, UnicodeError, RecursionError, zlib.error:
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
        content = await self.read_body(response)
        data = json.loads(content)
        if not isinstance(data, dict):
            raise ProviderError("invalid_response")
        return response.status_code, data

    async def read_body(self, response):
        encoding = response.headers.get("content-encoding", "identity").strip().lower()
        if encoding not in {"identity", "gzip"}:
            raise ProviderError("invalid_response")
        decoder = (
            zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
        )
        content = bytearray()
        wire_bytes = 0
        # HTTPX's aiter_bytes decodes a complete compressed chunk before yielding it.
        # Read raw bytes instead and bound both wire size and every zlib allocation.
        async for chunk in response.aiter_raw(chunk_size=64 * 1024):
            wire_bytes += len(chunk)
            if wire_bytes > self.max_response_bytes:
                raise ProviderError("response_too_large")
            if decoder is not None:
                chunk = decoder.decompress(
                    chunk, self.max_response_bytes - len(content) + 1
                )
            if len(content) + len(chunk) > self.max_response_bytes:
                raise ProviderError("response_too_large")
            content.extend(chunk)
            if decoder is not None and decoder.unused_data:
                # Reject trailing bytes and concatenated members instead of silently
                # parsing just the first stream or starting an unbounded decoder.
                raise ProviderError("invalid_response")
        if decoder is not None and not decoder.eof:
            raise ProviderError("invalid_response")
        return content


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
