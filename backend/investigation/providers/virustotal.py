import base64
import re
from datetime import UTC, datetime
from urllib.parse import quote

from ..enrichment import EnrichmentResult, EnrichmentStatus, ProviderError, TargetKind
from ..enrichment import target as validate_target
from .http import MAX_SUBMISSION_BYTES, ProviderHTTP, count, mapping, text


class VirusTotalProvider(ProviderHTTP):
    name = "virustotal"
    origin = "https://www.virustotal.com"
    key_header = "x-apikey"
    lookup_kinds = ("sha256", "url", "domain", "ip")
    submission_kinds = ("file", "url")

    @staticmethod
    def job_id(value):
        if not isinstance(value, str) or not re.fullmatch(
            r"[A-Za-z0-9_=-]{1,256}", value
        ):
            raise ProviderError("invalid_job_id")
        return value

    @staticmethod
    def location(target):
        if target.kind in {TargetKind.FILE, TargetKind.SHA256}:
            return "files", target.value
        if target.kind == TargetKind.URL:
            return "urls", base64.urlsafe_b64encode(
                target.value.encode()
            ).decode().rstrip("=")
        if target.kind == TargetKind.DOMAIN:
            return "domains", target.value
        if target.kind == TargetKind.IP:
            return "ip_addresses", target.value
        raise ProviderError("unsupported_target")

    def link(self, target, url_id=None):
        kind, identifier = self.location(target)
        if target.kind == TargetKind.URL:
            # The web UI expects VT's canonical hash, not the API's base64 alias.
            if not isinstance(url_id, str) or not re.fullmatch(r"[a-f0-9]{64}", url_id):
                return None
            identifier = url_id
        gui_kind = {
            "files": "file",
            "urls": "url",
            "domains": "domain",
            "ip_addresses": "ip-address",
        }[kind]
        return f"{self.origin}/gui/{gui_kind}/{quote(identifier, safe='')}"

    async def lookup(self, target):
        target = validate_target(target.kind, target.value)
        if target.kind not in self.lookup_kinds:
            raise ProviderError("unsupported_target")
        kind, identifier = self.location(target)
        status, data = await self.request(
            "GET", f"/api/v3/{kind}/{quote(identifier, safe='')}"
        )
        if status in {404, 410}:
            return EnrichmentResult(
                self.name,
                target,
                EnrichmentStatus.UNKNOWN,
                summary="No existing report; nothing submitted.",
            )
        return self.normalize(target, data)

    async def submit(self, target, *, content=None, visibility="private"):
        target = validate_target(target.kind, target.value)
        if target.kind == TargetKind.FILE:
            if content is None or len(content) > MAX_SUBMISSION_BYTES:
                raise ProviderError("invalid_file_size")
            status, data = await self.request(
                "POST",
                "/api/v3/files",
                files={"file": ("evidence.bin", content, "application/octet-stream")},
            )
        elif target.kind == TargetKind.URL:
            status, data = await self.request(
                "POST", "/api/v3/urls", data={"url": target.value}
            )
        else:
            raise ProviderError("unsupported_target")
        if status in {404, 410}:
            raise ProviderError("request_rejected")
        job = self.job_id(mapping(data.get("data")).get("id"))
        return EnrichmentResult(
            self.name,
            target,
            EnrichmentStatus.PENDING,
            summary="Submission accepted; awaiting report.",
            external_id=job,
            external_url=self.link(target),
            metadata={"sharing": "standard_virustotal_submission"},
        )

    async def poll(self, target, external_id):
        target = validate_target(target.kind, target.value)
        external_id = self.job_id(external_id)
        status, data = await self.request("GET", f"/api/v3/analyses/{external_id}")
        if status in {404, 410}:
            return EnrichmentResult(
                self.name,
                target,
                EnrichmentStatus.UNAVAILABLE,
                summary="Analysis no longer available.",
                external_id=external_id,
            )
        if mapping(data.get("data")).get("id") != external_id:
            raise ProviderError("invalid_job_id")
        attributes = mapping(mapping(data.get("data")).get("attributes"))
        if attributes.get("status") in {"queued", "in-progress"}:
            return EnrichmentResult(
                self.name,
                target,
                EnrichmentStatus.PENDING,
                summary="Analysis pending.",
                external_id=external_id,
            )
        if attributes.get("status") != "completed":
            raise ProviderError("invalid_response")
        return self.normalize(target, data)

    def normalize(self, target, data):
        resource = mapping(data.get("data"))
        attributes = mapping(resource.get("attributes"))
        stats = mapping(attributes.get("last_analysis_stats", attributes.get("stats")))
        if not resource or not attributes:
            raise ProviderError("invalid_response")
        counts = {
            k: count(stats.get(k)) for k in ("malicious", "suspicious", "harmless")
        }
        unknown = count(stats.get("undetected"))
        seen = attributes.get("first_submission_date")
        seen = (
            datetime.fromtimestamp(seen, UTC).isoformat()
            if type(seen) is int and 0 <= seen <= 253402300799
            else None
        )
        external_id = resource.get("id")
        external_id = (
            self.job_id(external_id) if resource.get("type") == "analysis" else None
        )
        engines = mapping(
            attributes.get("last_analysis_results", attributes.get("results"))
        )
        labels = [
            text(mapping(v).get("result"), 120)
            for v in list(engines.values())[:200]
            if mapping(v).get("category") in {"malicious", "suspicious"}
        ]
        return EnrichmentResult(
            self.name,
            target,
            EnrichmentStatus.AVAILABLE,
            **counts,
            unknown=unknown,
            summary=f"VirusTotal: {counts['malicious'] if counts['malicious'] is not None else '?'} malicious; {counts['suspicious'] if counts['suspicious'] is not None else '?'} suspicious.",
            external_id=external_id,
            external_url=self.link(
                target,
                resource.get("id")
                if resource.get("type") == "url"
                else mapping(mapping(data.get("meta")).get("url_info")).get("id"),
            ),
            first_seen=seen,
            file_type=text(attributes.get("type_description")),
            metadata={
                "detection_labels": list(dict.fromkeys(v for v in labels if v))[:20],
                "reputation": attributes.get("reputation")
                if type(attributes.get("reputation")) is int
                else None,
            },
        )

    async def healthcheck(self):
        # A benign known empty-file hash probes authentication without sharing evidence.
        await self.request(
            "GET",
            "/api/v3/files/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )
        return {
            "status": "reachable",
            "detail": "Benign hash lookup accepted; licence and quotas are not certified.",
        }
