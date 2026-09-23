import re
from uuid import UUID

from ..enrichment import EnrichmentResult, EnrichmentStatus, ProviderError, TargetKind
from ..enrichment import target as validate_target
from .http import ProviderHTTP, mapping, strings, text


class UrlscanProvider(ProviderHTTP):
    name = "urlscan"
    origin = "https://urlscan.io"
    key_header = "api-key"
    lookup_kinds = ("url", "domain", "ip")
    submission_kinds = ("url",)

    @staticmethod
    def job_id(value):
        try:
            if not isinstance(value, str) or str(UUID(value)) != value:
                raise ValueError()
        except ValueError, AttributeError:
            raise ProviderError("invalid_job_id") from None
        return value

    async def lookup(self, target):
        target = validate_target(target.kind, target.value)
        field = {
            "url": "task.url.keyword",
            "domain": "page.domain.keyword",
            "ip": "page.ip",
        }.get(target.kind)
        if not field:
            raise ProviderError("unsupported_target")
        # A single quoted literal, with every reserved Query String character escaped.
        value = re.sub(r'([+\-=!(){}\[\]^"~*?:\\/<>|&])', r"\\\1", target.value.lower())
        status, data = await self.request(
            "GET", "/api/v1/search/", params={"q": f'{field}:"{value}"', "size": 1}
        )
        results = data.get("results", [])
        if status in {404, 410} or not results:
            return EnrichmentResult(
                self.name,
                target,
                EnrichmentStatus.UNKNOWN,
                summary="No existing scan; nothing submitted.",
            )
        if not isinstance(results, list) or not isinstance(results[0], dict):
            raise ProviderError("invalid_response")
        # Read the existing scan only; a search miss must never create a scan.
        record = results[0]
        job = self.job_id(record.get("_id") or mapping(record.get("task")).get("uuid"))
        return await self.poll(target, job)

    async def submit(self, target, *, content=None, visibility="private"):
        target = validate_target(target.kind, target.value)
        if target.kind != TargetKind.URL or visibility not in {
            "private",
            "unlisted",
            "public",
        }:
            raise ProviderError("unsupported_target")
        status, data = await self.request(
            "POST",
            "/api/v1/scan/",
            json={"url": target.value, "visibility": visibility},
        )
        if status in {404, 410}:
            raise ProviderError("request_rejected")
        job = self.job_id(data.get("uuid"))
        actual_visibility = data.get("visibility")
        if actual_visibility is not None and actual_visibility != visibility:
            # Preserve the accepted job so the incident is visible; never retry publicly.
            return EnrichmentResult(
                self.name,
                target,
                EnrichmentStatus.ERROR,
                summary="Provider returned an unexpected visibility; check the provider immediately.",
                external_id=job,
                external_url=f"{self.origin}/result/{job}/",
                metadata={
                    "requested_visibility": visibility,
                    "visibility": text(actual_visibility, 20),
                    "error_code": "visibility_mismatch",
                },
            )
        return EnrichmentResult(
            self.name,
            target,
            EnrichmentStatus.PENDING,
            summary="Scan accepted; awaiting report.",
            external_id=job,
            external_url=f"{self.origin}/result/{job}/",
            metadata={"visibility": visibility},
        )

    async def poll(self, target, external_id):
        target = validate_target(target.kind, target.value)
        job = self.job_id(external_id)
        status, data = await self.request("GET", f"/api/v1/result/{job}/")
        if status == 404:
            return EnrichmentResult(
                self.name,
                target,
                EnrichmentStatus.PENDING,
                summary="Scan pending.",
                external_id=job,
            )
        if status == 410:
            return EnrichmentResult(
                self.name,
                target,
                EnrichmentStatus.UNAVAILABLE,
                summary="Scan deleted by provider.",
                external_id=job,
            )
        actual = mapping(data.get("task")).get("uuid")
        if actual != job:
            raise ProviderError("invalid_job_id")
        return self.normalize(target, data)

    def normalize(self, target, data):
        task, page = mapping(data.get("task")), mapping(data.get("page"))
        job = self.job_id(task.get("uuid"))
        verdict = mapping(mapping(data.get("verdicts")).get("overall")) or mapping(
            mapping(data.get("verdicts")).get("urlscan")
        )
        malicious = verdict.get("malicious")
        score = verdict.get("score")
        score = score if type(score) is int and -100 <= score <= 100 else None
        # Chrome documents redirects via redirectResponse on document requests.
        chain = [text(task["url"], 2048)] if isinstance(task.get("url"), str) else []
        requests = mapping(data.get("data")).get("requests", [])
        if isinstance(requests, list):
            for entry in requests[:500]:
                request = mapping(mapping(entry).get("request"))
                response = mapping(request.get("redirectResponse"))
                if request.get("type") == "Document" and response.get("url"):
                    chain.append(text(response["url"], 2048))
        for value in (page.get("url"),):
            if value:
                chain.append(text(value, 2048))
        return EnrichmentResult(
            self.name,
            target,
            EnrichmentStatus.AVAILABLE,
            malicious=1 if malicious is True else (0 if malicious is False else None),
            unknown=1 if malicious is None else None,
            summary="urlscan flags malicious activity."
            if malicious is True
            else "urlscan report available; absence of a malicious verdict is not proof of safety.",
            external_id=job,
            external_url=f"{self.origin}/result/{job}/",
            first_seen=text(task.get("time"), 50),
            file_type=text(page.get("mimeType")),
            metadata={
                "visibility": text(task.get("visibility"), 20),
                "domain": text(page.get("domain")),
                "ip": text(page.get("ip")),
                "country": text(page.get("country"), 5),
                "title": text(page.get("title")),
                "score": score,
                "categories": strings(verdict.get("categories")),
                "redirect_chain": list(dict.fromkeys(v for v in chain if v))[:20],
                "redirect_chain_complete": False,
                "redirected": text(page.get("redirected")),
                "screenshot_url": f"{self.origin}/screenshots/{job}.png",
            },
        )

    async def healthcheck(self):
        status, _ = await self.request("GET", "/user/quotas/")
        if status in {404, 410}:
            raise ProviderError("request_rejected")
        return {
            "status": "reachable",
            "detail": "Quota endpoint accepted; private scan entitlement is checked on submission.",
        }
