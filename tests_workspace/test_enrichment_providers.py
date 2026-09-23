import asyncio
import gzip
import json
import unittest
import zlib
from unittest.mock import patch

import httpx

from backend.investigation.enrichment import ProviderError, target
from backend.investigation.providers.http import MAX_SUBMISSION_BYTES
from backend.investigation.providers.urlscan import UrlscanProvider
from backend.investigation.providers.virustotal import VirusTotalProvider

JOB = "a8caa11f-1221-433e-884f-d8545897c828"
URL = "https://suspicious.example/path?x=1&y=2"
HASH = "a" * 64


class ProviderContracts(unittest.IsolatedAsyncioTestCase):
    def transport(self, handler):
        self.requests = []

        def record(request):
            self.requests.append(request)
            response = handler(request)
            if response.is_stream_consumed:
                # Real responses reach client.stream before any body is consumed.
                response = httpx.Response(
                    response.status_code,
                    headers=response.headers,
                    stream=httpx.ByteStream(response.content),
                )
            return response

        return httpx.MockTransport(record)

    async def test_vt_unknown_is_one_get_no_submission(self):
        provider = VirusTotalProvider(
            "secret", transport=self.transport(lambda r: httpx.Response(404, json={}))
        )
        result = await provider.lookup(target("sha256", HASH))
        self.assertEqual(result.status, "unknown")
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.requests[0].method, "GET")
        self.assertEqual(
            str(self.requests[0].url), f"https://www.virustotal.com/api/v3/files/{HASH}"
        )
        self.assertEqual(self.requests[0].headers["x-apikey"], "secret")
        self.assertEqual(self.requests[0].headers["accept-encoding"], "identity")

    async def test_vt_normalizes_optional_counts_and_ignores_raw(self):
        data = {
            "data": {
                "id": HASH,
                "type": "file",
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 3,
                        "suspicious": 1,
                        "harmless": 4,
                        "undetected": 12,
                    },
                    "first_submission_date": 1700000000,
                    "type_description": "PDF",
                    "huge_secret_dump": "secret",
                },
            }
        }
        provider = VirusTotalProvider(
            "secret", transport=self.transport(lambda r: httpx.Response(200, json=data))
        )
        result = await provider.lookup(target("sha256", HASH))
        self.assertEqual(
            (result.malicious, result.suspicious, result.harmless, result.unknown),
            (3, 1, 4, 12),
        )
        self.assertEqual(result.file_type, "PDF")
        self.assertTrue(result.first_seen.startswith("2023-"))
        self.assertNotIn("raw", result.public())
        self.assertNotIn("secret", json.dumps(result.public()))

    async def test_vt_url_lookup_is_encoded_identifier(self):
        provider = VirusTotalProvider(
            "secret", transport=self.transport(lambda r: httpx.Response(404, json={}))
        )
        await provider.lookup(target("url", "http://169.254.169.254/latest/meta-data"))
        self.assertEqual(self.requests[0].url.host, "www.virustotal.com")
        self.assertTrue(self.requests[0].url.path.startswith("/api/v3/urls/"))
        self.assertNotIn("169.254", self.requests[0].url.path)

    async def test_vt_file_submit_multipart_and_pending_poll(self):
        provider = VirusTotalProvider(
            "secret",
            transport=self.transport(
                lambda r: httpx.Response(
                    200,
                    json={
                        "data": {
                            "id": "analysis-job_1=",
                            "type": "analysis",
                            "attributes": {"status": "queued"},
                        }
                    },
                )
            ),
        )
        result = await provider.submit(target("file", HASH), content=b"bytes")
        self.assertEqual(result.status, "pending")
        self.assertEqual(self.requests[0].url.path, "/api/v3/files")
        self.assertIn(b"evidence.bin", self.requests[0].content)
        self.assertIn(b"bytes", self.requests[0].content)
        result = await provider.poll(target("file", HASH), result.external_id)
        self.assertEqual(result.status, "pending")
        self.assertEqual(self.requests[-1].url.path, "/api/v3/analyses/analysis-job_1=")

    async def test_vt_url_submit_is_form(self):
        provider = VirusTotalProvider(
            "secret",
            transport=self.transport(
                lambda r: httpx.Response(200, json={"data": {"id": "job"}})
            ),
        )
        await provider.submit(target("url", URL))
        request = self.requests[0]
        self.assertEqual(request.url.path, "/api/v3/urls")
        self.assertEqual(
            request.headers["content-type"], "application/x-www-form-urlencoded"
        )
        self.assertIn(b"url=https", request.content)

    async def test_invalid_job_ids_never_contact_provider(self):
        for cls in (VirusTotalProvider, UrlscanProvider):
            provider = cls(
                "secret",
                transport=self.transport(lambda r: self.fail("Unexpected egress")),
            )
            for bad in (
                "../../secrets",
                "https://attacker.invalid",
                "",
                "job?key=secret",
            ):
                with self.assertRaises(ProviderError):
                    await provider.poll(target("url", URL), bad)
        self.assertEqual(self.requests, [])

    async def test_urlscan_default_private_and_no_visibility_fallback(self):
        provider = UrlscanProvider(
            "secret",
            transport=self.transport(
                lambda r: httpx.Response(403, text="secret plan denied")
            ),
        )
        with self.assertRaisesRegex(ProviderError, "credentials_or_plan_rejected"):
            await provider.submit(target("url", URL))
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(
            json.loads(self.requests[0].content), {"url": URL, "visibility": "private"}
        )

    async def test_urlscan_visibilities_and_mismatch(self):
        for visibility in ("private", "unlisted", "public"):
            provider = UrlscanProvider(
                "secret",
                transport=self.transport(
                    lambda r, visibility=visibility: httpx.Response(
                        200,
                        json={
                            "uuid": JOB,
                            "visibility": visibility,
                            "api": "http://127.0.0.1/steal",
                        },
                    )
                ),
            )
            result = await provider.submit(target("url", URL), visibility=visibility)
            self.assertEqual(result.status, "pending")
            self.assertEqual(
                json.loads(self.requests[0].content)["visibility"], visibility
            )
            self.assertEqual(result.external_url, f"https://urlscan.io/result/{JOB}/")
        provider = UrlscanProvider(
            "secret",
            transport=self.transport(
                lambda r: httpx.Response(
                    200, json={"uuid": JOB, "visibility": "public"}
                )
            ),
        )
        result = await provider.submit(target("url", URL))
        self.assertEqual(result.status, "error")
        self.assertEqual(result.metadata["error_code"], "visibility_mismatch")
        self.assertEqual(len(self.requests), 1)

    async def test_urlscan_search_escapes_query_and_never_submits_miss(self):
        provider = UrlscanProvider(
            "secret",
            transport=self.transport(
                lambda r: httpx.Response(200, json={"results": []})
            ),
        )
        result = await provider.lookup(target("url", 'https://a.example/?x=" OR *'))
        self.assertEqual(result.status, "unknown")
        query = self.requests[0].url.params["q"]
        self.assertTrue(query.startswith('task.url.keyword:"'))
        self.assertIn(r"\"", query)
        self.assertIn(r"\*", query)
        self.assertEqual([r.method for r in self.requests], ["GET"])

    async def test_urlscan_existing_search_result_and_safe_links(self):
        def reply(request):
            if request.url.path == "/api/v1/search/":
                return httpx.Response(
                    200, json={"results": [{"_id": JOB, "task": {"url": URL}}]}
                )
            return httpx.Response(
                200,
                json={
                    "task": {
                        "uuid": JOB,
                        "url": URL,
                        "visibility": "private",
                        "screenshotURL": "javascript:evil",
                    },
                    "page": {
                        "domain": "destination.example",
                        "ip": "192.0.2.4",
                        "url": "https://destination.example/",
                        "title": "<script>",
                    },
                    "verdicts": {"overall": {"malicious": True, "score": 80}},
                },
            )

        provider = UrlscanProvider("secret", transport=self.transport(reply))
        result = await provider.lookup(target("url", URL))
        self.assertEqual(result.malicious, 1)
        self.assertEqual(result.metadata["ip"], "192.0.2.4")
        self.assertEqual(
            result.metadata["screenshot_url"],
            f"https://urlscan.io/screenshots/{JOB}.png",
        )
        self.assertEqual(
            result.metadata["redirect_chain"], [URL, "https://destination.example/"]
        )
        self.assertFalse(result.metadata["redirect_chain_complete"])
        self.assertEqual(len(self.requests), 2)
        self.assertTrue(all(r.url.host == "urlscan.io" for r in self.requests))

    async def test_urlscan_url_lookup_preserves_path_query_case_and_verifies_identity(
        self,
    ):
        original = "HTTPS://SUSPICIOUS.Example/Phish?Token=AbC&X=%2F#Report"
        canonical = "https://suspicious.example/Phish?Token=AbC&X=%2F#Report"

        def reply(request):
            record = {"task": {"uuid": JOB, "url": canonical}}
            if request.url.path == "/api/v1/search/":
                return httpx.Response(200, json={"results": [record]})
            return httpx.Response(200, json=record)

        provider = UrlscanProvider("secret", transport=self.transport(reply))
        result = await provider.lookup(target("url", original))
        query = self.requests[0].url.params["q"]
        self.assertIn("Phish", query)
        self.assertIn("Token", query)
        self.assertIn("AbC", query)
        self.assertIn("%2F", query)
        self.assertNotIn("SUSPICIOUS", query)
        self.assertEqual(result.target.value, original)
        self.assertEqual(result.status, "available")
        self.assertEqual(
            UrlscanProvider.url_identity("https://EXAMPLE.org/Path?#"),
            "https://example.org/Path?#",
        )

    async def test_urlscan_rejects_search_and_report_url_mismatches(self):
        original = "https://suspicious.example/Phish?Token=AbC"
        for wrong in (original.lower(), "https://other.example/Phish?Token=AbC", None):
            for wrong_stage in ("search", "report"):
                with self.subTest(wrong=wrong, stage=wrong_stage):

                    def reply(request, wrong=wrong, wrong_stage=wrong_stage):
                        search = request.url.path == "/api/v1/search/"
                        record = {
                            "task": {
                                "uuid": JOB,
                                "url": wrong
                                if search == (wrong_stage == "search")
                                else original,
                            }
                        }
                        return httpx.Response(
                            200, json={"results": [record]} if search else record
                        )

                    provider = UrlscanProvider(
                        "secret", transport=self.transport(reply)
                    )
                    with self.assertRaisesRegex(ProviderError, "invalid_response"):
                        await provider.lookup(target("url", original))
                    self.assertEqual(
                        len(self.requests), 1 if wrong_stage == "search" else 2
                    )
                    self.assertTrue(
                        all(request.method == "GET" for request in self.requests)
                    )

    async def test_transport_gzip_output_is_bounded_before_allocation(self):
        cap = 1024
        compressed = gzip.compress(json.dumps({"long": "A" * (1024 * 1024)}).encode())
        actual_decoder = zlib.decompressobj
        allocations = []

        class BoundedDecoder:
            def __init__(self, *args):
                self.decoder = actual_decoder(*args)

            def decompress(self, data, max_length=0):
                self.assert_bound(max_length)
                result = self.decoder.decompress(data, max_length)
                allocations.append(len(result))
                return result

            def assert_bound(self, max_length):
                if not 0 < max_length <= cap + 1:
                    raise AssertionError("Unbounded decompression")

            def __getattr__(self, name):
                return getattr(self.decoder, name)

        # Fit the compressed wire bytes under the cap so the output bound is tested.
        cap = len(compressed) + 100
        provider = VirusTotalProvider(
            "secret",
            max_response_bytes=cap,
            transport=self.transport(
                lambda r: httpx.Response(
                    200,
                    headers={"Content-Encoding": "gzip"},
                    stream=httpx.ByteStream(compressed),
                )
            ),
        )
        with (
            patch(
                "backend.investigation.providers.http.zlib.decompressobj",
                BoundedDecoder,
            ),
            patch(
                "httpx._decoders.GZipDecoder.decode",
                side_effect=AssertionError("Automatic HTTPX decoding"),
            ),
            self.assertRaisesRegex(ProviderError, "response_too_large"),
        ):
            await provider.lookup(target("sha256", HASH))
        self.assertEqual(allocations, [cap + 1])

    async def test_transport_accepts_bounded_gzip_and_rejects_invalid_encodings(self):
        body = json.dumps({"answer": "value"}).encode()
        compressed = gzip.compress(body)
        for payload, encoding, error in (
            (compressed, "gzip", None),
            (body, "identity", None),
            (compressed[:-5], "gzip", "invalid_response"),
            (compressed + b"unexpected", "gzip", "invalid_response"),
            (compressed + compressed, "gzip", "invalid_response"),
            (b"broken gzip", "gzip", "invalid_response"),
            (compressed, "br", "invalid_response"),
            (compressed, "gzip, gzip", "invalid_response"),
        ):
            with self.subTest(encoding=encoding, error=error):
                provider = VirusTotalProvider(
                    "secret",
                    transport=self.transport(
                        lambda r, encoding=encoding, payload=payload: httpx.Response(
                            200,
                            headers={"Content-Encoding": encoding},
                            stream=httpx.ByteStream(payload),
                        )
                    ),
                )
                if error:
                    with self.assertRaisesRegex(ProviderError, error):
                        await provider.request("GET", "/test")
                else:
                    self.assertEqual(
                        await provider.request("GET", "/test"),
                        (200, {"answer": "value"}),
                    )

    async def test_transport_enforces_the_same_exact_size_boundary_for_gzip_and_identity(
        self,
    ):
        expected = {"answer": "A" * 1000}
        body = json.dumps(expected).encode()
        for encoding, wire in (("identity", body), ("gzip", gzip.compress(body))):
            for cap in (len(body), len(body) - 1):
                with self.subTest(encoding=encoding, cap=cap):
                    provider = VirusTotalProvider(
                        "secret",
                        max_response_bytes=cap,
                        transport=self.transport(
                            lambda r, encoding=encoding, wire=wire: httpx.Response(
                                200,
                                headers={"Content-Encoding": encoding},
                                stream=httpx.ByteStream(wire),
                            )
                        ),
                    )
                    if cap == len(body):
                        self.assertEqual(
                            await provider.request("GET", "/test"), (200, expected)
                        )
                    else:
                        with self.assertRaisesRegex(
                            ProviderError, "response_too_large"
                        ):
                            await provider.request("GET", "/test")

    async def test_urlscan_poll_pending_deleted_mismatched(self):
        for status, expected in ((404, "pending"), (410, "unavailable")):
            provider = UrlscanProvider(
                "secret",
                transport=self.transport(
                    lambda r, status=status: httpx.Response(status)
                ),
            )
            self.assertEqual(
                (await provider.poll(target("url", URL), JOB)).status, expected
            )
        provider = UrlscanProvider(
            "secret",
            transport=self.transport(
                lambda r: httpx.Response(200, json={"task": {"uuid": "different"}})
            ),
        )
        with self.assertRaises(ProviderError):
            await provider.poll(target("url", URL), JOB)

    async def test_transport_rejects_redirect_error_invalid_json_and_large_response(
        self,
    ):
        responses = [
            (302, {"location": "http://127.0.0.1/"}, "", "request_rejected"),
            (429, {}, "secret quota", "rate_limited"),
            (200, {}, "secret invalid JSON", "invalid_response"),
            (200, {}, json.dumps({"long": "x" * 400}), "response_too_large"),
        ]
        for code, headers, body, expected in responses:
            provider = VirusTotalProvider(
                "secret",
                max_response_bytes=100,
                transport=self.transport(
                    lambda r, code=code, headers=headers, body=body: httpx.Response(
                        code, headers=headers, text=body
                    )
                ),
            )
            with self.assertRaisesRegex(ProviderError, expected):
                await provider.lookup(target("sha256", HASH))
            self.assertEqual(len(self.requests), 1)

    async def test_timeout_is_total_and_sanitized(self):
        async def slow(request):
            await asyncio.sleep(0.1)
            return httpx.Response(200, json={})

        provider = VirusTotalProvider(
            "secret", timeout=0.01, transport=httpx.MockTransport(slow)
        )
        with self.assertRaisesRegex(ProviderError, "timeout"):
            await provider.lookup(target("sha256", HASH))

    async def test_oversized_submission_fails_before_network(self):
        provider = VirusTotalProvider(
            "secret", transport=self.transport(lambda r: self.fail("Unexpected egress"))
        )
        with self.assertRaisesRegex(ProviderError, "invalid_file_size"):
            await provider.submit(
                target("file", HASH), content=b"x" * (MAX_SUBMISSION_BYTES + 1)
            )

    async def test_healthchecks_are_benign_fixed_endpoints(self):
        for cls, path in (
            (
                VirusTotalProvider,
                "/api/v3/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (UrlscanProvider, "/user/quotas/"),
        ):
            provider = cls(
                "secret",
                transport=self.transport(
                    lambda r: httpx.Response(
                        200, json={"quota": "sensitive response ignored"}
                    )
                ),
            )
            result = await provider.healthcheck()
            self.assertEqual(result["status"], "reachable")
            self.assertNotIn("sensitive", json.dumps(result))
            self.assertEqual(self.requests[0].url.path, path)


if __name__ == "__main__":
    unittest.main()
