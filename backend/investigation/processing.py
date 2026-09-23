"""Provider-independent report helpers."""

def extract_iocs(result):
    eml = result.get("eml", {})
    values = set()
    fields = {
        "urls": "url",
        "domains": "domain",
        "emails": "email",
        "ip_addresses": "ip",
    }
    for body in eml.get("bodies", []):
        for field, kind in fields.items():
            values.update(
                (kind, value.strip()) for value in body.get(field, []) if value.strip()
            )
    header = eml.get("header", {})
    for field, kind in [
        ("received_domain", "domain"),
        ("received_ip", "ip"),
        ("received_email", "email"),
    ]:
        values.update(
            (kind, value.strip()) for value in header.get(field) or [] if value.strip()
        )
    for attachment in eml.get("attachments", []):
        digest = attachment.get("hash", {}).get("sha256")
        if digest:
            values.add(("sha256", digest))
    return {
        (kind, value.lower() if kind in ("domain", "sha256") else value)
        for kind, value in values
    }


def expected_engines(document, optional_email_rep, optional_vt, optional_urlscan):
    expected = ["SpamAssassin", "oleid"]
    if any(
        k.lower() == "dkim-signature"
        for k in document["eml"]["header"].get("header", {})
    ):
        expected.append("DKIM")
    if optional_email_rep is not None and document["eml"]["header"].get("from_"):
        expected.append("EmailRep")
    if optional_vt is not None:
        expected.append("VirusTotal")
    if optional_urlscan is not None:
        expected.append("urlscan.io")
    return expected

