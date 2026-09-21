import unittest

from backend.investigation.enrichment import (
    EnrichmentDisabled,
    EnrichmentPolicy,
    EnrichmentResult,
    EnrichmentStatus,
    EnrichmentTarget,
    TargetKind,
    lookup,
    submit,
)


class FakeProvider:
    name = "fake"

    def __init__(self):
        self.lookups = 0
        self.submissions = 0

    async def lookup(self, target):
        self.lookups += 1
        return EnrichmentResult(self.name, target, EnrichmentStatus.UNKNOWN)

    async def submit(self, target, *, content=None):
        self.submissions += 1
        return EnrichmentResult(self.name, target, EnrichmentStatus.AVAILABLE)


class EnrichmentPolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_offline_never_calls_provider(self):
        provider = FakeProvider()
        target = EnrichmentTarget(TargetKind.SHA256, "a" * 64)
        with self.assertRaises(EnrichmentDisabled):
            await lookup(provider, target, EnrichmentPolicy(online=False, external_lookups=True))
        self.assertEqual(provider.lookups, 0)

    async def test_lookup_does_not_require_submission_permission(self):
        provider = FakeProvider()
        target = EnrichmentTarget(TargetKind.SHA256, "a" * 64)
        result = await lookup(
            provider,
            target,
            EnrichmentPolicy(online=True, external_lookups=True, file_submission=False),
        )
        self.assertEqual(result.status, EnrichmentStatus.UNKNOWN)
        self.assertEqual(provider.lookups, 1)
        self.assertEqual(provider.submissions, 0)

    async def test_file_submission_is_explicitly_gated(self):
        provider = FakeProvider()
        target = EnrichmentTarget(TargetKind.FILE, "attachment.bin")
        with self.assertRaises(EnrichmentDisabled):
            await submit(
                provider,
                target,
                EnrichmentPolicy(online=True, external_lookups=True, file_submission=False),
                content=b"sample",
            )
        self.assertEqual(provider.submissions, 0)

    async def test_file_submission_requires_bytes(self):
        provider = FakeProvider()
        target = EnrichmentTarget(TargetKind.FILE, "attachment.bin")
        with self.assertRaises(ValueError):
            await submit(
                provider,
                target,
                EnrichmentPolicy(online=True, file_submission=True),
            )
        self.assertEqual(provider.submissions, 0)


if __name__ == "__main__":
    unittest.main()
