# Architecture

Vue → FastAPI → durable queue → bounded parser subprocess → SQLite metadata and
filesystem EvidenceStorage. Original files and attachment bytes are immutable;
analyst decisions, notes, IOC classifications and campaigns are separate records.
Reports expose normalized evidence and engine coverage, never infer safety merely
from missing detections. Similarity results list exact shared signals; they are
correlation hints, not proof of common attribution.

Community is MIT and single-team. Enterprise is a separate private repository that
pins Community as a Git submodule. It mounts shared investigation routes through
explicit database/storage/auth/connectivity hooks, with PostgreSQL organization
schemas and a distinct identity/control plane. No commercial implementation is
required to run Community. See OPEN_CORE.md and the unchanged upstream LICENSE.

Extension hooks are ContextVars with safe Community defaults: database_factory,
storage_factory, ingestion_guard, connectivity.policy_factory and
providers.credentials_factory. An adapter must set/reset every tenant context,
check membership server-side, fail closed on absent credentials, and version its
own migrations. Tenant IDs supplied by browser payloads cannot establish authority.

The private adapter owns billing, tenancy, invitations, trial policy, operator
console, retention and outgoing webhooks. It must not copy/fork shared parsers or
silently replace a pinned core version. Contract and isolation tests accompany each
submodule update. Advanced SSO connectors and MSSP operations remain future work
until explicitly implemented and tested.
