# Folio investigation workflows

PhishCase keeps its own identity, database and sessions. The shared Folio visual language has no authentication integration with SafeScan. Fonts and CSS ship locally.

## Working paths

The reception page exposes EML/MSG upload immediately and lists actual recent messages and the signed-in analyst's cases. Each direct upload retains its original evidence and creates a case assigned to the uploading analyst. Cases offer My cases and Team views; existing admin/analyst/viewer permissions remain authoritative.

Analysis opens the neutralized message beside automated results and a separate analyst decision. Eight existing verdicts, confidence, justification and append-only history remain intact. Message resources are never fetched. Indices/correlations, enrichment/technical details and reporter follow-up are separate tabs. Case tabs distinguish investigation, response/actions, sourced intelligence and notes/timeline.

Primary navigation contains Reception, Cases, Indices, Campaigns and Actions. Explorer contains overview, all analyses, global search and sourced intelligence. Profile retains account security, integrations, permitted user administration and Cloud account links; menus support keyboard, Escape and outside dismissal. On mobile, the five primary paths and Explorer remain visible.

Short task guides are optional, dismissible and replayable. Interface and known operation errors remain available in French and English.

## Operational records

`case_actions` stores owner, due date, status, proof/result, author and revision. Completion and cancellation require a documented result/reason. A closed case cannot receive new or changed actions. Closing a case requires no pending action, no message still processing, no completed message awaiting analyst qualification and no reply being transmitted.

`reporter_replies` stores an explicit recipient, draft, immutable accepted transmission and state. The suspicious email sender is never auto-selected as reporter. Drafts are persisted before preview. HTML-looking text stays text. An analyst explicitly sends the exact preview revision. A reply tied to an analysis requires an active analyst decision.

SMTP requires `SMTP_HOST` and `SMTP_FROM`; STARTTLS is the default and `SMTP_SSL=true` selects implicit TLS. `SMTP_PORT`, `SMTP_USERNAME`, and `SMTP_PASSWORD` configure the optional authenticated transport. Cloud uses its existing SMTP or Mailgun transport. Lack of transport preserves the draft and disables sending. The send result states acceptance by transport, never proof of recipient delivery/reading. No real delivery occurs in tests.

The send is recorded as `sending` before the network call. A timeout/failure becomes `uncertain`; process interruption can leave `sending`. Neither is automatically retried, avoiding duplicate replies. The analyst's Reconcile transmission result operation records a verified acceptance or failure, requires a transport reference/evidence and the read revision, and retains the operator, time, proof and audit trail. Verified acceptance unlocks closure without claiming inbox delivery. A verified failure can be explicitly edited back to a draft, previewed and sent; reconciliation itself never transmits. Accepted replies cannot be edited or resent. A late transport result cannot overwrite a concurrently reconciled revision.

`intelligence_links` stores human-entered sources, observed facts, counter-evidence, hypothesis, observation date and analyst confidence, with optional case/campaign links. Sources are text references, never remotely retrieved. No automatic attribution or generated confidence score is introduced. Existing exact IOC and message similarity reasons remain available and are never automatic case merges.

JSON/HTML investigation exports include operational actions, analysis-linked reporter replies and case intelligence. Originals/manifests and explicitly selected attachment bundles preserve their previous behavior.

## Concurrency and storage

Cases, actions, drafts and intelligence use monotonic revisions. Current UI sends the revision it read and surfaces HTTP 409 rather than overwriting a colleague's work. Decisions send their last-seen decision ID. Existing case/decision API clients without revision fields remain compatible; adopting the version field is required for their optimistic concurrency protection.

Community startup applies additive, idempotent SQLite schema revision `2026101001`. Originals and previous metadata are preserved. The initialization lock remains in place. Backup includes all operational records through the existing whole-database snapshot.

Cloud upgrades every tenant to `20261010_tenant_0002` via Alembic revision `20261010_0004`; newly provisioned tenants receive the same schema. Every query uses the existing verified tenant context and schema bridge. Organization checks and role controls remain in force. Analysis retention previews include linked reporter replies and refuse purge during a transmission. Operational records remain part of encrypted PostgreSQL backups.

Deploy after a verified database/evidence backup. Stop application and worker traffic, build the Community image, build Enterprise from that exact image, run `python -m cloud.manage migrate` with the configured PostgreSQL URL, then restart services. Community migrates on next startup. Destructive downgrade is refused; use a verified compatible backup for rollback.

## Validation

New real SQLite and PostgreSQL integration tests cover persistence, repeat initialization, assignees, stale versions, controlled closure, tenant isolation, viewer permissions, explicit preview/send, unavailable transport and uncertain transmission. Vue tests verify inert preview content, read-only restrictions and explicit revision-bound send. Existing investigation, evidence, account, enrichment, retention and backup suites must also pass.
