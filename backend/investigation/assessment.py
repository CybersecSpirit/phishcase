"""Conservative triage summary: heuristic flags are not confirmed malware."""


def summarize(document: dict, *, expected: list[str] | None = None) -> dict:
    verdicts = document.get("verdicts", [])
    reported = {v["name"] for v in verdicts}
    expected = expected if expected is not None else ["SpamAssassin"]
    missing = sorted(set(expected) - reported)
    flagged = [v for v in verdicts if v.get("malicious")]
    detections = [v for v in flagged if v["name"] in ("VirusTotal", "urlscan.io")]
    reasons = [
        f"{v['name']} : {d['description']}"
        for v in flagged
        for d in v.get("details", [])
    ]
    if detections:
        level, label = "malicious", "Détection malveillante"
        explanation = "Un moteur de réputation signale un élément malveillant. Consultez les preuves ci-dessous."
    elif flagged:
        level, label = "suspicious", "Email suspect"
        explanation = "Des signaux suspects ont été détectés. Ils nécessitent une vérification avant de conclure."
    elif missing or not verdicts:
        level, label = "inconclusive", "Résultat incomplet"
        explanation = "Les contrôles disponibles ne permettent pas de conclure ; aucun verdict de sécurité fiable ne peut être donné."
    else:
        level, label = "no_signal", "Aucun signal détecté"
        explanation = "Aucun signal remonté par les contrôles disponibles. Cela ne garantit pas que cet email ou ses pièces jointes sont sûrs."
    return {
        "level": level,
        "label": label,
        "explanation": explanation,
        "reasons": reasons,
        "reported_engines": sorted(reported),
        "missing_engines": missing,
        "scope": "Analyse statique et moteurs disponibles ; aucune exécution des pièces jointes en sandbox. Une empreinte inconnue des services de réputation reste non vérifiée.",
    }
