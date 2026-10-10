"""Bound MIME complexity and advertised ZIP expansion without extracting files."""

from email import policy
from email.parser import BytesParser
from io import BytesIO
from zipfile import BadZipFile, ZipFile, is_zipfile


def validate_message(data):
    message = BytesParser(policy=policy.default).parsebytes(data)
    pending = [(message, 0)]
    parts = decoded = 0
    while pending:
        part, depth = pending.pop()
        parts += 1
        if parts > 200 or depth > 20:
            raise ValueError("MIME complexity limit exceeded")
        if part.is_multipart():
            pending.extend((child, depth + 1) for child in part.get_payload())
            continue
        content = part.get_payload(decode=True) or b""
        decoded += len(content)
        if decoded > 30 * 1024 * 1024:
            raise ValueError("Decoded message limit exceeded")
        if content.startswith(b"PK") and is_zipfile(BytesIO(content)):
            validate_zip(content)


def validate_zip(data):
    try:
        with ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            total = sum(item.file_size for item in entries)
            if len(entries) > 1000 or total > 100 * 1024 * 1024:
                raise ValueError("Archive expansion limit exceeded")
            if any(
                item.file_size > 1024 * 1024
                and item.file_size > 200 * max(1, item.compress_size)
                for item in entries
            ):
                raise ValueError("Archive compression ratio limit exceeded")
    except BadZipFile as exc:
        raise ValueError("Malformed archive") from exc
