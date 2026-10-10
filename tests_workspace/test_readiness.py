import errno
import os
import sqlite3
import stat
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.investigation import readiness
from backend.investigation.store import db, initialize


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name) / "evidence"
        self.root.mkdir()
        self.original = self.root / "immutable-example"
        self.original.write_bytes(b"Existing evidence must remain untouched")

    def tearDown(self):
        self.directory.cleanup()

    def assert_original_only(self):
        self.assertEqual(list(self.root.iterdir()), [self.original])
        self.assertEqual(
            self.original.read_bytes(), b"Existing evidence must remain untouched"
        )

    def test_probe_performs_real_write_fsync_and_removes_only_its_private_file(self):
        kinds = []
        real_fsync = os.fsync

        def observed_fsync(descriptor):
            attributes = os.fstat(descriptor)
            if stat.S_ISREG(attributes.st_mode):
                kinds.append("file")
                self.assertEqual(stat.S_IMODE(attributes.st_mode), 0o600)
                self.assertEqual(attributes.st_size, 4096)
                probe = next(self.root.glob(".phishcase-ready-*"))
                self.assertEqual(probe.read_bytes(), readiness.PROBE_BYTES)
            else:
                kinds.append("directory")
            return real_fsync(descriptor)

        with patch.object(readiness.os, "fsync", side_effect=observed_fsync):
            self.assertTrue(readiness.storage_ready(self.root))
        self.assertEqual(kinds, ["file", "directory"])
        self.assert_original_only()

    def test_permission_denied_on_creation_is_not_hidden_by_access_bits(self):
        real_open = os.open

        def denied(path, flags, mode=0o777, *, dir_fd=None):
            if dir_fd is not None:
                raise PermissionError(errno.EACCES, "private storage path")
            return real_open(path, flags, mode)

        self.assertTrue(os.access(self.root, os.W_OK))
        with patch.object(readiness.os, "open", side_effect=denied):
            self.assertFalse(readiness.storage_ready(self.root))
        self.assert_original_only()

    def test_low_available_space_refuses_before_probe_creation(self):
        with (
            patch.object(
                readiness.os,
                "fstatvfs",
                return_value=SimpleNamespace(
                    f_bavail=readiness.MIN_FREE_BYTES - 1, f_frsize=1
                ),
            ),
            patch.object(
                readiness,
                "uuid4",
                side_effect=AssertionError("No probe when reserve is exhausted"),
            ),
        ):
            self.assertFalse(readiness.storage_ready(self.root))
        self.assert_original_only()

    def test_full_filesystem_reported_at_flush_cleans_created_probe(self):
        with patch.object(
            readiness.os,
            "fsync",
            side_effect=OSError(errno.ENOSPC, "private volume detail"),
        ):
            self.assertFalse(readiness.storage_ready(self.root))
        self.assert_original_only()

    def test_failed_deletion_is_not_ready_and_cleanup_retries_its_own_probe(self):
        real_unlink = os.unlink
        calls = []

        def fail_once(path, *, dir_fd=None):
            calls.append(path)
            if len(calls) == 1:
                raise PermissionError(errno.EACCES, "private directory")
            return real_unlink(path, dir_fd=dir_fd)

        with patch.object(readiness.os, "unlink", side_effect=fail_once):
            self.assertFalse(readiness.storage_ready(self.root))
        self.assertEqual(calls[0], calls[1])
        self.assert_original_only()

    def test_collision_does_not_delete_the_existing_file(self):
        existing = self.root / (".phishcase-ready-" + "a" * 32)
        existing.write_bytes(b"Pre-existing file")
        with patch.object(
            readiness, "uuid4", return_value=SimpleNamespace(hex="a" * 32)
        ):
            self.assertFalse(readiness.storage_ready(self.root))
        self.assertEqual(existing.read_bytes(), b"Pre-existing file")

    def test_community_ready_contract_checks_real_storage_and_bounds_database_failure(
        self,
    ):
        from backend import main

        with patch.dict(
            os.environ,
            {
                "INVESTIGATION_DB": str(Path(self.directory.name) / "workspace.db"),
                "EVIDENCE_ROOT": str(self.root),
            },
        ):
            initialize()
            with db() as conn:
                conn.execute(
                    "INSERT INTO worker_heartbeats(id,seen) VALUES (?,?)",
                    ("readiness-test", time.time()),
                )
            client = TestClient(main.create_app())
            try:
                response = client.get("/ready")
                self.assertEqual(
                    (response.status_code, response.json()), (200, {"status": "ready"})
                )
                with patch.object(
                    readiness.os,
                    "fstatvfs",
                    return_value=SimpleNamespace(f_bavail=0, f_frsize=4096),
                ):
                    response = client.get("/ready")
                    self.assertEqual(
                        (response.status_code, response.json()),
                        (503, {"status": "not_ready"}),
                    )
                with patch.object(
                    main,
                    "db",
                    side_effect=sqlite3.OperationalError(
                        "secret hostname/path/password"
                    ),
                ):
                    response = client.get("/ready")
                    self.assertEqual(
                        (response.status_code, response.json()),
                        (503, {"status": "not_ready"}),
                    )
                self.assertEqual(client.get("/health").json(), {"status": "ok"})
            finally:
                client.close()
        self.assert_original_only()
