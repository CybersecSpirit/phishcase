"""A small, destructive-only-to-its-own-probe filesystem readiness check."""

import os
from contextlib import suppress
from uuid import uuid4

MIN_FREE_BYTES = 256 * 1024 * 1024
PROBE_BYTES = b"\0" * 4096


def storage_ready(root):
    """Check actual durable writes and cleanup without returning paths or errors.

    The caller owns directory provisioning. This function never removes existing
    evidence or a colliding file: cleanup is restricted to a successful O_EXCL
    creation in the opened directory. Linux and macOS expose f_bavail for the
    space available to the service account, excluding privileged reserves.
    """
    directory, descriptor, created = None, None, None
    try:
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        space = os.fstatvfs(directory)
        if space.f_bavail * space.f_frsize < MIN_FREE_BYTES:
            return False
        name = ".phishcase-ready-" + uuid4().hex
        descriptor = os.open(
            name,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
            dir_fd=directory,
        )
        created = name
        stream = os.fdopen(descriptor, "wb")
        descriptor = None  # The stream owns and closes the file descriptor now.
        with stream:
            if stream.write(PROBE_BYTES) != len(PROBE_BYTES):
                return False
            stream.flush()
            os.fsync(stream.fileno())
        os.unlink(created, dir_fd=directory)
        created = None
        os.fsync(directory)
        return True
    except OSError, ValueError:
        return False
    finally:
        if descriptor is not None:
            with suppress(OSError):
                os.close(descriptor)
        if created is not None:
            with suppress(OSError):
                os.unlink(created, dir_fd=directory)
        if directory is not None:
            os.close(directory)
