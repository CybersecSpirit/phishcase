"""Human reports and explicitly selected evidence bundles; no active email HTML."""

import hashlib
import html
import io
import json
import zipfile

from fastapi import APIRouter, HTTPException, Query, Response

from .auth import User
from .evidence import original, storage
from .store import audit, db

router = APIRouter()


def report_document(analysis_id, user):
    # Local import avoids coupling the core endpoint to export formats.
    from .api import get_analysis

    document = get_analysis(analysis_id, user)
    with db() as conn:
        document["analyst_decisions"] = [
            dict(row)
            for row in conn.execute(
                "SELECT d.*,u.username FROM analyst_decisions d LEFT JOIN users u ON u.id=d.actor_id WHERE analysis_id=? ORDER BY d.id",
                (analysis_id,),
            )
        ]
        document["iocs"] = [
            dict(row)
            for row in conn.execute(
                "SELECT i.kind,i.value,i.verdict FROM iocs i JOIN analysis_iocs ai ON ai.ioc_id=i.id WHERE ai.analysis_id=? ORDER BY i.kind,i.value",
                (analysis_id,),
            )
        ]
        document["timeline"] = [
            dict(row)
            for row in conn.execute(
                "SELECT action,detail,created_at FROM events WHERE case_id=? ORDER BY id",
                (document["case_id"],),
            )
        ]
        document["campaigns"] = [
            dict(row)
            for row in conn.execute(
                "SELECT c.id,c.name,c.description FROM campaigns c JOIN campaign_cases cc ON cc.campaign_id=c.id WHERE cc.case_id=? AND c.deleted_at IS NULL",
                (document["case_id"],),
            )
        ]
    return document


def download(content, media_type, filename):
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            "Cache-Control": "no-store",
        },
    )


@router.get("/analyses/{analysis_id}/export.json")
def json_report(analysis_id: str, user: User):
    return download(
        json.dumps(report_document(analysis_id, user), ensure_ascii=False, indent=2),
        "application/json",
        f"phishcase-{analysis_id}.json",
    )


def rendered_report(document, locale="en"):  # noqa: C901 - linear report sections
    def value_text(value):
        if isinstance(value, dict):
            return "; ".join(str(k) + ": " + value_text(v) for k, v in value.items())
        if isinstance(value, list):
            return ", ".join(value_text(v) for v in value)
        return str(value if value is not None else "")

    def escape(value):
        return html.escape(value_text(value))

    def tr(en, fr):
        return fr if locale == "fr" else en

    def table(rows):
        return (
            "<table>"
            + "".join(
                "<tr><th>" + escape(k) + "</th><td>" + escape(v) + "</td></tr>"
                for k, v in rows
            )
            + "</table>"
        )

    def section(title, rows):
        return "<h2>" + escape(title) + "</h2>" + table(rows)

    report = document.get("result") or {}
    email = report.get("eml") or {}
    header = email.get("header") or {}
    parts = [
        "<!doctype html><html lang='"
        + locale
        + "'><meta charset='utf-8'><meta name='referrer' content='no-referrer'><title>PhishCase report</title><style>body{font:16px system-ui;color:#14283a;max-width:960px;margin:40px auto;padding:24px}table{border-collapse:collapse;width:100%}th,td{padding:8px;text-align:left;border-bottom:1px solid #ddd;overflow-wrap:anywhere}pre{white-space:pre-wrap;overflow-wrap:anywhere}h2{margin-top:32px}</style><h1>PhishCase · "
        + tr("Investigation report", "Rapport d'investigation")
        + "</h1>"
    ]
    parts.append(
        table(
            [
                (k, document.get(k))
                for k in (
                    "id",
                    "case_id",
                    "filename",
                    "sha256",
                    "created_at",
                    "ingestion_source",
                    "status",
                )
            ]
        )
    )
    parts.append(
        section(
            "Email",
            [
                (k, header.get(k))
                for k in ("subject", "from_", "to", "date", "message_id")
            ],
        )
    )
    parts.append("<h2>" + tr("Analyst decisions", "Décisions analystes") + "</h2>")
    decisions = document.get("analyst_decisions", [])
    if not decisions:
        parts.append(
            "<p>"
            + tr(
                "No analyst decision recorded.", "Aucune décision analyste enregistrée."
            )
            + "</p>"
        )
    for item in decisions:
        parts.append(
            table(
                [
                    (k, item.get(k))
                    for k in (
                        "action",
                        "verdict",
                        "confidence",
                        "justification",
                        "username",
                        "created_at",
                    )
                ]
            )
        )
    assessment = document.get("assessment") or {}
    parts.append(
        section(
            tr("Automated assessment", "Évaluation automatique"),
            [
                (k, assessment.get(k))
                for k in (
                    "label",
                    "explanation",
                    "reasons",
                    "reported_engines",
                    "missing_engines",
                )
            ],
        )
    )
    for verdict in report.get("verdicts", []):
        parts.append(
            "<h3>"
            + escape(verdict.get("name"))
            + "</h3>"
            + table([(k, verdict.get(k)) for k in ("malicious", "score", "details")])
        )
    parts.append(
        "<h2>" + tr("Indicators (defanged)", "Indicateurs (neutralisés)") + "</h2>"
    )
    parts.append(
        table(
            [
                (
                    item["kind"],
                    item["value"]
                    .replace("https://", "hxxps://")
                    .replace("http://", "hxxp://")
                    .replace(".", "[.]"),
                )
                for item in document.get("iocs", [])
            ]
        )
    )
    parts.append("<h2>" + tr("Attachments", "Pièces jointes") + "</h2>")
    for item in email.get("attachments", []):
        parts.append(
            table([(k, item.get(k)) for k in ("filename", "mime_type", "size", "hash")])
        )
    parts.append(
        section(
            tr("Campaigns", "Campagnes"),
            [
                (item.get("name"), item.get("description"))
                for item in document.get("campaigns", [])
            ],
        )
    )
    parts.append(
        section(
            tr("Timeline", "Chronologie"),
            [
                (
                    item.get("created_at"),
                    str(item.get("action")) + " · " + str(item.get("detail")),
                )
                for item in document.get("timeline", [])
            ],
        )
    )
    parts.append(
        "<p>"
        + tr(
            "No detection does not establish that an email is safe.",
            "L'absence de détection ne garantit pas l'innocuité.",
        )
        + "</p></html>"
    )
    return "".join(parts)


@router.get("/analyses/{analysis_id}/export.html")
def html_report(analysis_id: str, user: User, locale: str = "en"):
    return download(
        rendered_report(
            report_document(analysis_id, user), "fr" if locale == "fr" else "en"
        ),
        "text/html",
        f"phishcase-{analysis_id}.html",
    )


@router.get("/analyses/{analysis_id}/evidence.zip")
def evidence_package(
    analysis_id: str, user: User, attachments: str = Query(default="", max_length=4096)
):
    document = report_document(analysis_id, user)
    try:
        selection = sorted({int(value) for value in attachments.split(",") if value})
    except ValueError as exc:
        raise HTTPException(422, "Invalid attachment selection") from exc
    metadata = (document.get("result") or {}).get("eml", {}).get("attachments", [])
    if any(value < 0 or value >= len(metadata) for value in selection):
        raise HTTPException(422, "Invalid attachment selection")
    with db() as conn:
        raw = original(conn, analysis_id)
        suffix = "msg" if document["filename"].lower().endswith(".msg") else "eml"
        files = {
            "original." + suffix: raw,
            "report.json": json.dumps(document, ensure_ascii=False, indent=2).encode(),
        }
        for index in selection:
            row = conn.execute(
                "SELECT * FROM evidence_attachments WHERE analysis_id=? AND position=?",
                (analysis_id, index),
            ).fetchone()
            if not row:
                raise HTTPException(409, "Attachment migration required")
            files[f"attachments/attachment-{index + 1}.bin"] = storage().read(
                row["storage_key"], row["sha256"]
            )
        audit(conn, user["id"], "evidence.exported", document["case_id"], analysis_id)
    manifest = {
        name: {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content)}
        for name, content in files.items()
    }
    files["manifest.json"] = json.dumps(
        {
            "analysis_id": analysis_id,
            "files": manifest,
            "warning": "Attachments may be malicious. Do not execute them.",
        },
        indent=2,
    ).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return download(
        buffer.getvalue(), "application/zip", f"phishcase-evidence-{analysis_id}.zip"
    )
