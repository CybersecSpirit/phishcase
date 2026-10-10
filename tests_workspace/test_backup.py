import io
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from backend.investigation.backup import (
    community_backup,
    create_key,
    restore,
    unpack_verified,
)
from backend.investigation.evidence import original
from backend.investigation.jobs import enqueue
from backend.investigation.store import create_admin, db


class BackupTests(unittest.TestCase):
    def test_live_snapshot_restore_preserves_original_and_queue_and_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.dict(os.environ, {"INVESTIGATION_DB": str(root / "source.db")}):
                create_admin("test", "Synthetic-test-12345")
                with db() as conn:
                    user = dict(conn.execute("SELECT * FROM users").fetchone())
                analysis = enqueue(
                    b"From: qa@example.org\r\n\r\nSynthetic.", "qa.eml", user
                )
                create_key(root / "backup.key")
                (root / "config.env").write_text(
                    "MFA_ENCRYPTION_KEY=synthetic-qa-value\n"
                )
                community_backup(
                    root / "snapshot.pcbk", root / "backup.key", root / "config.env"
                )
                restore(root / "snapshot.pcbk", root / "restored", root / "backup.key")
            with patch.dict(
                os.environ,
                {"INVESTIGATION_DB": str(root / "restored/phishcase.sqlite3")},
            ):
                with db() as conn:
                    self.assertEqual(
                        original(conn, analysis),
                        b"From: qa@example.org\r\n\r\nSynthetic.",
                    )
                    self.assertEqual(
                        conn.execute("SELECT state FROM jobs").fetchone()[0], "queued"
                    )
                    self.assertEqual(
                        conn.execute("PRAGMA integrity_check").fetchone()[0], "ok"
                    )
                self.assertEqual(
                    (root / "restored/configuration.env").read_text(),
                    (root / "config.env").read_text(),
                )
                self.assertNotIn(
                    b"synthetic-qa-value", (root / "snapshot.pcbk").read_bytes()
                )
                with self.assertRaises(ValueError):
                    restore(
                        root / "snapshot.pcbk", root / "restored", root / "backup.key"
                    )
            data = bytearray((root / "snapshot.pcbk").read_bytes())
            data[-20] ^= 1
            (root / "bad.pcbk").write_bytes(data)
            with self.assertRaises(InvalidTag):
                restore(root / "bad.pcbk", root / "tampered", root / "backup.key")
            self.assertFalse((root / "tampered").exists())

    def test_restore_rejects_paths_and_links_without_writing_target(self):
        for name, kind in [
            ("../outside", tarfile.REGTYPE),
            ("symlink", tarfile.SYMTYPE),
        ]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                with tarfile.open(root / "bad.tar", "w") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "/etc/passwd"
                    member.size = 0
                    archive.addfile(member, io.BytesIO(b""))
                with self.assertRaises(ValueError):
                    unpack_verified(root / "bad.tar", root / "target")
                self.assertEqual(list((root / "target").iterdir()), [])
                self.assertFalse((root / "outside").exists())
