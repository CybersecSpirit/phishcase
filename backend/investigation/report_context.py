"""Derived, local investigation context for new and historical saved reports.

Never rewrite parser evidence: this projection is calculated when reading a report.
Received entries are already oldest-first in EmlFactory's persisted contract.
"""

import re
from email.utils import getaddresses
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from .enrichment_api import decode


def addresses(values):
    return [
        {
            "display_name": name,
            "address": address,
            "domain": address.rsplit("@", 1)[1].casefold() if "@" in address else "",
        }
        for name, address in getaddresses(values)
        if address or name
    ]


def domain(value):
    try:
        return (urlsplit(value).hostname or "").casefold()
    except ValueError:
        return ""


def raw_headers(header):
    return {
        key.casefold(): [str(item) for item in value]
        if isinstance(value, list)
        else [str(value)]
        for key, value in (header.get("header") or {}).items()
    }


def identity(header):
    headers = raw_headers(header)
    raw_from = ", ".join(headers.get("from", []))
    parsed = addresses(headers.get("from", []) or [header.get("from_") or ""])
    sender = parsed[0] if parsed else {"display_name": "", "address": "", "domain": ""}
    result = {
        **sender,
        "raw_from": raw_from or header.get("from_") or "",
        "reply_to": addresses(headers.get("reply-to", [])),
        "return_path": addresses(headers.get("return-path", [])),
        "anomalies": [],
    }
    for kind in ("reply_to", "return_path"):
        if sender["domain"] and any(
            item["domain"] and item["domain"] != sender["domain"]
            for item in result[kind]
        ):
            result["anomalies"].append(
                {
                    "code": kind + "_domain_differs",
                    "message": kind.replace("_", "-")
                    + " domain differs from From; forwarding and legitimate senders can also cause this.",
                }
            )
    displayed = re.findall(
        r"[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})|\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b",
        sender["display_name"],
    )
    if sender["domain"] and any(
        (email_domain or name_domain).casefold() != sender["domain"]
        for email_domain, name_domain in displayed
    ):
        result["anomalies"].append(
            {
                "code": "display_name_domain_differs",
                "message": "The display name mentions a different domain; check possible impersonation in context.",
            }
        )
    return result


def declared_authentication(header):
    declarations = []
    for source, values in raw_headers(header).items():
        if source not in {
            "authentication-results",
            "arc-authentication-results",
            "received-spf",
        }:
            continue
        for raw in values:
            authserv = raw.split(";", 1)[0].strip() if source != "received-spf" else ""
            mechanisms = list(
                re.finditer(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z_-]+)([^;]*)", raw, re.I)
            )
            if source == "received-spf":
                first = raw.split(None, 1)
                fields = [("spf", first[0] if first else "unknown", raw)]
            else:
                fields = [
                    (m[1].lower(), m[2].lower(), m[3].strip()) for m in mechanisms
                ]
            for mechanism, result, detail in fields:
                declarations.append(
                    {
                        "source": source,
                        "raw": raw,
                        "authserv_id": authserv,
                        "mechanism": mechanism,
                        "result": result,
                        "detail": detail,
                        "confidence": "unverified",
                    }
                )
    return {"declared": declarations}


def local_content(document):
    email = document.get("eml") or {}
    header = email.get("header") or {}
    texts, links = [], {}
    for index, body in enumerate(email.get("bodies") or []):
        content = body.get("content") or ""
        content_type = body.get("content_type") or "text/plain"
        text = content
        if "html" in content_type.casefold():
            soup = BeautifulSoup(content, "html.parser")
            for element in soup(["script", "style", "noscript", "template"]):
                element.decompose()
            text = soup.get_text("\n", strip=True)
            for anchor in soup.find_all("a", href=True):
                href = str(anchor.get("href"))
                if href.startswith(("http://", "https://")):
                    links.setdefault(href, set()).add(anchor.get_text(" ", strip=True))
        texts.append({"index": index, "content_type": content_type, "text": text})
        for url in body.get("urls") or []:
            links.setdefault(url, set())
    return {
        "identity": identity(header),
        "routing": {"order": "oldest_first", "hops": header.get("received") or []},
        "authentication": declared_authentication(header),
        "bodies": texts,
        "urls": [
            {
                "value": value,
                "domain": domain(value),
                "display_texts": sorted(text for text in labels if text),
                "destination_mismatch": any(
                    domain(label) and domain(label) != domain(value) for label in labels
                ),
            }
            for value, labels in links.items()
        ],
    }


def enrichments(conn, analysis_id):
    # API admission caps history at 1000 rows; preserve every stored observation
    # in exports, including unavailable checks and their provenance.
    return [
        decode(row)
        for row in conn.execute(
            "SELECT * FROM enrichments WHERE analysis_id=? ORDER BY created_at DESC,id DESC",
            (analysis_id,),
        )
    ]


def investigation_context(conn, analysis_id, document):
    context = local_content(document)
    iocs = {
        (row["kind"], row["value"]): dict(row)
        for row in conn.execute(
            """SELECT i.id AS ioc_id,i.kind,i.value,
            (SELECT count(*) FROM analysis_iocs x WHERE x.ioc_id=i.id) AS analysis_count,
            (SELECT count(DISTINCT a.case_id) FROM analysis_iocs x JOIN analyses a ON a.id=x.analysis_id WHERE x.ioc_id=i.id) AS case_count
            FROM iocs i JOIN analysis_iocs own ON own.ioc_id=i.id WHERE own.analysis_id=?""",
            (analysis_id,),
        )
    }
    campaigns = {}
    for row in conn.execute(
        """SELECT DISTINCT ai.ioc_id,c.id,c.name FROM analysis_iocs ai
        JOIN analyses a ON a.id=ai.analysis_id JOIN campaign_cases cc ON cc.case_id=a.case_id
        JOIN campaigns c ON c.id=cc.campaign_id WHERE c.deleted_at IS NULL
        AND ai.ioc_id IN (SELECT ioc_id FROM analysis_iocs WHERE analysis_id=?) ORDER BY c.id""",
        (analysis_id,),
    ):
        campaigns.setdefault(row["ioc_id"], []).append(
            {"id": row["id"], "name": row["name"]}
        )
    latest = {}
    for item in enrichments(conn, analysis_id):
        key = (item["provider"], item["target"]["kind"], item["target"]["value"])
        latest.setdefault(key, item)

    def related(kind, value):
        ioc = iocs.get((kind, value), {})
        return {
            "ioc_id": ioc.get("ioc_id"),
            "analysis_count": ioc.get("analysis_count", 0),
            "case_count": ioc.get("case_count", 0),
            "campaigns": campaigns.get(ioc.get("ioc_id"), []),
            "enrichments": [
                item
                for (_, target_kind, target_value), item in latest.items()
                if target_value == value
                and target_kind in {kind, "file" if kind == "sha256" else kind}
            ],
        }

    for url in context["urls"]:
        url.update(related("url", url["value"]))
    context["attachments"] = []
    for index, attachment in enumerate(
        (document.get("eml") or {}).get("attachments") or []
    ):
        sha256 = (attachment.get("hash") or {}).get("sha256", "")
        context["attachments"].append(
            {
                "index": index,
                "filename": attachment.get("filename", ""),
                "sha256": sha256,
                **related("sha256", sha256),
                "static_findings": [
                    detail
                    for verdict in document.get("verdicts") or []
                    if verdict.get("name") == "oleid"
                    for detail in verdict.get("details") or []
                    if sha256 and sha256 in detail.get("description", "")
                ],
            }
        )
    return context
