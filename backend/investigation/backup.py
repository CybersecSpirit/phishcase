"""Encrypted, verifiable Community snapshots. Restore always uses an empty target.

The wrapping helpers also protect Enterprise PostgreSQL/evidence backup bundles.
Keep the 32-byte backup key separately: it is never included in the archive.
"""

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import tarfile
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MAGIC = b"PHISHCASE-BACKUP-1\n"
CHUNK = 1024 * 1024


def key_bytes(path):
    key = Path(path).read_bytes()
    if len(key) != 32:
        raise ValueError("Backup key must contain exactly 32 random bytes")
    return key


def create_key(path):
    with os.fdopen(
        os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
    ) as out:
        out.write(os.urandom(32))


def encrypt_file(source, destination, key):
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(MAGIC)
    with (
        open(source, "rb") as src,
        os.fdopen(
            os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
        ) as out,
    ):
        out.write(MAGIC + nonce)
        for chunk in iter(lambda: src.read(CHUNK), b""):
            out.write(encryptor.update(chunk))
        out.write(encryptor.finalize())
        out.write(encryptor.tag)
        out.flush()
        os.fsync(out.fileno())


def decrypt_file(source, destination, key):
    """Do not consume destination until this returns: final tag authenticates it."""
    with open(source, "rb") as src:
        if src.read(len(MAGIC)) != MAGIC:
            raise ValueError("Unsupported backup format")
        nonce = src.read(12)
        src.seek(-16, os.SEEK_END)
        tag = src.read(16)
        remaining = src.tell() - len(MAGIC) - 12 - 16
        if remaining < 0:
            raise ValueError("Truncated backup")
        src.seek(len(MAGIC) + 12)
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(MAGIC)
        try:
            with os.fdopen(
                os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb"
            ) as out:
                while remaining:
                    chunk = src.read(min(CHUNK, remaining))
                    if not chunk:
                        raise ValueError("Truncated backup")
                    remaining -= len(chunk)
                    out.write(decryptor.update(chunk))
                out.write(decryptor.finalize())
        except BaseException:
            Path(destination).unlink(missing_ok=True)
            raise


def digest(path):
    with open(path, "rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def pack(root, output):
    root = Path(root)
    files = {}
    for item in sorted(root.rglob("*")):
        if item.is_symlink():
            raise ValueError("Backup source contains a symlink")
        if item.is_file():
            files[item.relative_to(root).as_posix()] = {
                "sha256": digest(item),
                "size": item.stat().st_size,
            }
    if "manifest.json" in files:
        raise ValueError("Reserved manifest path")
    (root / "manifest.json").write_text(
        json.dumps({"format": 1, "files": files}, indent=2)
    )
    with tarfile.open(output, "w") as archive:
        for name in [*files, "manifest.json"]:
            archive.add(root / name, arcname=name, recursive=False)


def unpack_verified(archive_path, target):
    """No archive paths, links, modes or ownership are trusted."""
    target = Path(target)
    if target.exists() and any(target.iterdir()):
        raise ValueError("Restore target must be empty")
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(
        prefix="phishcase-restore-", dir=target.parent
    ) as tmp:
        staging = Path(tmp)
        with tarfile.open(archive_path, "r:") as archive:
            members = archive.getmembers()
            if len(members) > 1_000_000:
                raise ValueError("Too many backup members")
            seen = set()
            for member in members:
                name = Path(member.name)
                if (
                    not member.isfile()
                    or name.is_absolute()
                    or ".." in name.parts
                    or "\\" in member.name
                    or member.name in seen
                    or name.as_posix() != member.name
                ):
                    raise ValueError("Unsafe or duplicate backup member")
                seen.add(member.name)
                destination = staging / name
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with archive.extractfile(member) as src, destination.open("xb") as out:
                    shutil.copyfileobj(src, out, CHUNK)
                destination.chmod(0o600)
        manifest = json.loads((staging / "manifest.json").read_text())
        if manifest.get("format") != 1 or set(manifest["files"]) != seen - {
            "manifest.json"
        }:
            raise ValueError("Backup manifest mismatch")
        for name, item in manifest["files"].items():
            path = staging / name
            if path.stat().st_size != item["size"] or digest(path) != item["sha256"]:
                raise ValueError("Backup checksum mismatch")
        for item in staging.iterdir():
            shutil.move(str(item), target / item.name)


def community_backup(output, key_path, config=None):
    from .evidence import storage
    from .store import db

    with tempfile.TemporaryDirectory(prefix="phishcase-backup-") as tmp:
        root = Path(tmp) / "snapshot"
        root.mkdir(mode=0o700)
        database = root / "phishcase.sqlite3"
        with db() as source, sqlite3.connect(database) as snapshot:
            source.backup(snapshot)
        database.chmod(0o600)
        evidence = root / "evidence"
        evidence.mkdir(mode=0o700)
        with sqlite3.connect(database) as conn:
            items = conn.execute(
                "SELECT source_ref,sha256 FROM analyses WHERE source_ref IS NOT NULL UNION SELECT storage_key,sha256 FROM evidence_attachments"
            ).fetchall()
        store = storage()
        for key, expected in items:
            raw = store.read(key, expected)
            (evidence / key).write_bytes(raw)
            (evidence / key).chmod(0o600)
        if config:
            shutil.copyfile(config, root / "configuration.env")
            (root / "configuration.env").chmod(0o600)
        # Preserve the locally generated MFA key, or explicitly capture the
        # externally supplied value inside the encrypted bundle only.
        mfa_key = os.environ.get("MFA_ENCRYPTION_KEY")
        local_key = Path(
            os.environ.get("INVESTIGATION_DB", "data/investigation.sqlite3")
            + ".mfa.key"
        )
        if mfa_key:
            (root / "phishcase.sqlite3.mfa.key").write_text(mfa_key)
        elif local_key.exists():
            shutil.copyfile(local_key, root / "phishcase.sqlite3.mfa.key")
        if (root / "phishcase.sqlite3.mfa.key").exists():
            (root / "phishcase.sqlite3.mfa.key").chmod(0o600)
        pack(root, Path(tmp) / "snapshot.tar")
        encrypt_file(Path(tmp) / "snapshot.tar", output, key_bytes(key_path))


def restore(source, target, key_path):
    with tempfile.TemporaryDirectory(prefix="phishcase-decrypt-") as tmp:
        archive = Path(tmp) / "backup.tar"
        decrypt_file(source, archive, key_bytes(key_path))
        unpack_verified(archive, target)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("keygen")
    init.add_argument("path")
    backup = commands.add_parser("backup")
    backup.add_argument("output")
    backup.add_argument("--key", required=True)
    backup.add_argument(
        "--config", help="Configuration file to include inside encrypted bundle"
    )
    recovery = commands.add_parser("restore")
    recovery.add_argument("source")
    recovery.add_argument("target")
    recovery.add_argument("--key", required=True)
    args = parser.parse_args()
    if args.command == "keygen":
        create_key(args.path)
    elif args.command == "backup":
        community_backup(args.output, args.key, args.config)
    else:
        restore(args.source, args.target, args.key)
    print("Completed. Keep the backup key separately from the encrypted archive.")  # noqa: T201 - CLI status


if __name__ == "__main__":
    main()
