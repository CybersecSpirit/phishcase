# Community installation and operations

PhishCase Community is a single-team application. Every active member can read
the team's evidence. Use the separate Enterprise adapter for organization isolation.
French installation and account instructions are in [README](../README.md).

## Start

Requirements: Git, Docker Engine and Docker Compose. Copy `.env.example` to `.env`,
then run `docker compose -p phishcase up -d --build`. Create the initial administrator
with `docker compose -p phishcase exec phishcase python -m backend.investigation.store`.
No default account exists. The service binds to `127.0.0.1:8088`.

Use an HTTPS reverse proxy and `COOKIE_SECURE=true` for shared access. Set a 21 MiB
request body limit in the proxy. Upload responses are asynchronous; a 60-second
proxy timeout is sufficient. No WebSocket support is required. Never expose the
Docker daemon, SQLite volume or evidence directory through the web server.

The root Compose file includes `compose.phishcase.yml`. `docs/upstream-compose.yml`
is historical reference, not the product deployment entry point. Redis is unused.

## Evidence and jobs

The `/data` volume includes metadata, immutable evidence, and an optional generated
MFA encryption key. Files have opaque names, mode 0600, and SHA-256 verification.
File downloads are authenticated, attachments, no-store and nosniff. Protect the
host volume with access controls and disk encryption when required. Evidence files
are not individually encrypted at rest by the application.

The API acknowledges an upload only after persisting its original and queue row.
A worker reserves a job with a unique expiring lease. Late workers cannot overwrite
a newer attempt. A stopped worker's job is recovered after the lease expires
(default parser timeout 180 seconds plus 60 seconds). Retries stop after three
attempts; the original remains available and an analyst can explicitly retry.

The parser runs in a subprocess: 120 CPU seconds, configurable 768 MiB address-space
limit on Linux, 64 MiB report size, 128 file descriptors, wall-clock timeout. MIME
depth is at most 20 with 200 parts. ZIP metadata is checked for excessive expansion;
archives and executables are never run or recursively extracted. These boundaries
are not an operating-system malware sandbox. Restrict container networking for
an additional enforceable offline perimeter.

`CONNECTIVITY_MODE=offline` is the default. Restricted permits configured lookups;
connected additionally permits explicitly enabled submissions. See ENRICHMENTS.md.
Do not put keys in Git, query strings or browser JavaScript.

## Health and logs

`/health` confirms HTTP liveness. `/ready` also checks SQLite, usable evidence
storage and a worker heartbeat within five minutes. Storage readiness requires
at least **256 MiB available to the service account**, a fixed minimum reserve
in `backend/investigation/readiness.py`. In the evidence directory it exclusively
creates a unique 0600 probe, writes 4 KiB, flushes and fsyncs it, removes only that
probe, then fsyncs the directory. The configured root must be a real directory,
not a final-component symlink. Read-only mounts, write/flush/delete failures or
insufficient space return 503; SQLite failures also return 503 with only
`{"status":"not_ready"}`, without paths or exception details. A passing probe
is a point-in-time check, not a reservation of future upload capacity. Existing
evidence is never removed by the health check. The same helper is used by Cloud.
Inspect `docker compose -p phishcase logs --tail=100`. HTTP application logs use
route templates rather than URL queries; parser logs do not include message content.
Dependency and process-manager logs can still use their own formats.

## Migrations and rollback

Startup serializes idempotent, additive SQLite migrations with a filesystem lock.
The successful schema revision is recorded in `schema_migrations` (2026092301).
Legacy original BLOBs and inline attachment bytes are moved only after writing and
verifying immutable evidence. Failures stop startup; do not delete the old database.
A newer schema revision is refused by older code. Back up before upgrading, retain
the exact previous image and restore the matching backup for rollback. Do not assume
an old image understands a newer database. The Enterprise adapter uses separate,
explicit PostgreSQL/Alembic migrations.

## Encrypted backup and restoration

The maintenance CLI uses streaming AES-256-GCM and a SHA-256 manifest. A modified
archive, wrong key, unsafe path or symlink is rejected. Restoration never overwrites
a nonempty target. SQLite's backup API captures a consistent metadata snapshot;
only referenced immutable files are copied and verified. Pause the API/worker for
operational snapshots when coordinating with external retention or storage tools.

Inside an operator environment containing the application and mounted `/data`:

```sh
python -m backend.investigation.backup keygen /secure/backup.key
python -m backend.investigation.backup backup /backup/phishcase.pcbk --key /secure/backup.key --config /secure/phishcase.env
python -m backend.investigation.backup restore /backup/phishcase.pcbk /restore/new --key /secure/backup.key
```

Mount `/secure`, `/backup` and `/restore` explicitly when using Docker; do not add
them as public web volumes. The archive contains `phishcase.sqlite3`, its evidence,
the generated/external MFA key if present, and the explicitly supplied configuration.
Set `INVESTIGATION_DB` to the restored database and `EVIDENCE_ROOT` to its evidence
directory. Restore the configuration separately; check target paths before using it.
Start the same release with the restored volume and verify readiness, login, one
original download hash and one queued analysis. A successful database import alone
does not prove evidence or MFA recovery.

Suggested operator policy: daily encrypted backups, seven daily and four weekly
copies, with an independently controlled off-host destination. This schedule is a
documented recommendation, not automatically installed. Keep the backup key in a
separate password manager/offline recovery location. Loss of that key makes backups
unrecoverable. Loss of the MFA encryption key prevents decrypting existing TOTP
secrets. Test restoration after every schema change and at least monthly.

## Local development

Python 3.14, Node 24, libmagic and uv are required. Run `uv sync --frozen`, then
`npm ci && npm run build` in `frontend`. Start both `uv run uvicorn backend.main:app`
and `uv run python -m backend.investigation.jobs` with matching database/storage env.
Use a separate data directory and synthetic fixtures. `uv run python -m pytest
tests_workspace` tests the application. Historical `tests/` need SpamAssassin;
set `SPAMASSASSIN_EXTERNAL=true` and its port to reuse an existing local instance.
