from email.message import EmailMessage
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

from backend.investigation.parser_limits import validate_message, validate_zip


def test_archive_bomb_rejected_from_metadata_without_extraction():
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr("large.txt", b"0" * (2 * 1024 * 1024))
    with pytest.raises(ValueError, match="compression ratio"):
        validate_zip(buffer.getvalue())


def test_excessive_mime_parts_rejected_and_plain_message_accepted():
    validate_message(b"From: example@example.org\r\n\r\nHarmless.")
    message = EmailMessage()
    message.set_content("Harmless body.")
    for _ in range(201):
        message.add_attachment(
            b"x", maintype="application", subtype="octet-stream", filename="sample.bin"
        )
    with pytest.raises(ValueError, match="complexity"):
        validate_message(message.as_bytes())
