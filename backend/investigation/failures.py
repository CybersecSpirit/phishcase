"""Finite, non-sensitive analysis failure vocabulary for storage and the UI."""

MESSAGES = {
    "parser_timeout": "Analysis timed out. Original preserved; retry available.",
    "resource_limit": "Analysis exceeded a resource limit. Original preserved.",
    "parser_rejected": "The parser could not read this message. Original preserved.",
    "report_limit": "The analysis report exceeded the size limit. Original preserved.",
    "evidence_unavailable": "Original evidence is unavailable. Check storage before retrying.",
    "evidence_integrity": "Original evidence failed its integrity check. Analysis stopped.",
    "storage_unavailable": "The result could not be saved. Check storage before retrying.",
    "analysis_failed": "Analysis failed. Original preserved; retry available.",
}


class AnalysisError(ValueError):
    def __init__(self, code):
        self.code = code if code in MESSAGES else "analysis_failed"
        super().__init__(self.code)


def failure_message(error, phase):
    if isinstance(error, AnalysisError):
        code = error.code
    elif phase == "evidence":
        code = (
            "evidence_integrity"
            if isinstance(error, ValueError)
            else "evidence_unavailable"
        )
    elif phase == "persistence":
        code = "storage_unavailable"
    else:
        code = "parser_rejected" if isinstance(error, ValueError) else "analysis_failed"
    return f"[{code}] {MESSAGES[code]}"


def error_code(message):
    prefix = (message or "").split("]", 1)[0].removeprefix("[")
    return prefix if prefix in MESSAGES else None
