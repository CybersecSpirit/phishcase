# Folio investigation workflows

PhishCase keeps its own identity, database and sessions. The shared Folio visual language has no authentication integration with SafeScan. Fonts and CSS ship locally.

## Working paths

The reception page exposes EML/MSG upload immediately, recent emails, analyses to review, campaigns to follow and frequent IoC. Upload preserves an independent email with its original evidence and analysis. Grouping is optional: select emails to create a campaign or attach them to an existing one. An email can belong to several campaigns; detaching it preserves its evidence and decision.

Analysis opens the neutralized message beside automated results and a separate analyst decision. Eight existing verdicts, confidence, justification and append-only history remain intact. Message resources are never fetched. IoC/correlations, enrichment/technical details and reporter follow-up are separate tabs. Campaign tabs contain member emails, response/actions, sourced intelligence, notes/timeline and IoC. Campaigns carry collective owner, priority, status and assessment; each email keeps its own verdict.

Primary navigation contains Reception, Emails, IoC, Campaigns and Actions. Explorer contains overview, global search and sourced intelligence. Profile retains account security, integrations, permitted user administration and Cloud account links; menus support keyboard, Escape and outside dismissal. On mobile, the five primary paths and Explorer remain visible. My campaigns and Team filters organize assignment without changing role permissions.

Short task guides are optional, dismissible and replayable. Interface and known operation errors remain available in French and English.

## Operational records

`case_actions` stores owner, due date, status, proof/result, author and revision. Completion and cancellation require a documented result/reason. A closed campaign cannot receive new or changed collective actions. Closing a campaign requires no pending action, no message still processing, no completed message awaiting analyst qualification and no reply being transmitted.

`reporter_replies` stores an explicit recipient, draft, immutable accepted transmission and state. The suspicious email sender is never auto-selected as reporter. Drafts are persisted before preview. HTML-looking text stays text. An analyst explicitly sends the exact preview revision. A reply tied to an analysis requires an active analyst decision.

SMTP requires `SMTP_HOST` and `SMTP_FROM`; STARTTLS is the default and `SMTP_SSL=true` selects implicit TLS. `SMTP_PORT`, `SMTP_USERNAME`, and `SMTP_PASSWORD` configure the optional authenticated transport. Cloud uses its existing SMTP or Mailgun transport. Lack of transport preserves the draft and disables sending. The send result states acceptance by transport, never proof of recipient delivery/reading. No real delivery occurs in tests.

The send is recorded as `sending` before the network call. A timeout/failure becomes `uncertain`; process interruption can leave `sending`. Neither is automatically retried, avoiding duplicate replies. The analyst's Reconcile transmission result operation records a verified acceptance or failure, requires a transport reference/evidence and the read revision, and retains the operator, time, proof and audit trail. Verified acceptance unlocks closure without claiming inbox delivery. A verified failure can be explicitly edited back to a draft, previewed and sent; reconciliation itself never transmits. Accepted replies cannot be edited or resent. A late transport result cannot overwrite a concurrently reconciled revision.

`intelligence_links` stores human-entered sources, observed facts, counter-evidence, hypothesis, observation date and analyst confidence, with optional campaign links (historical case references remain in the archive). Sources are text references, never remotely retrieved. No automatic attribution or generated confidence score is introduced. Existing exact IoC and message similarity reasons remain available and are never automatic campaign merges.

JSON/HTML investigation exports include operational actions, analysis-linked reporter replies campaign intelligence, notes, timeline and collective replies. Originals/manifests and explicitly selected attachment bundles preserve their previous behavior.

## Concurrency and storage

Campaigns, memberships, actions, drafts and intelligence use monotonic revisions. Current UI sends the revision it read and surfaces HTTP 409 rather than overwriting a colleague's work. Decisions send their last-seen decision ID. Existing case/decision API clients without revision fields remain compatible; adopting the version field is required for their optimistic concurrency protection.

Community startup applies transactional, idempotent SQLite schema revision `2026101002` under the initialization lock. Cloud upgrades every tenant with `20261010_tenant_0003` via Alembic revision `20261010_0005`; new tenants receive the same schema. Original evidence, decisions, histories and useful legacy context are preserved by the [conservative migration](EMAIL_CAMPAIGNS.md). Old case links resolve to their email or migrated campaign. Deprecated case APIs remain only for historical client compatibility; new integrations use email/campaign routes.

Every Cloud query uses the verified tenant context and schema bridge. Organization checks and role controls remain in force. Retention previews include campaign memberships and refuse purge during a transmission; collective campaign context and audit survive email retention. Whole-database encrypted backups include the new records.

Stop app and worker, create a database/evidence/key backup, verify restoration to an isolated empty target, migrate that copy and verify conservation before production migration. Build Enterprise from the exact committed Community image. After independent emails have been written, an image-only rollback is unsafe: preserve current data and repair compatibly, or restore separately and reconcile subsequent writes. Destructive downgrade is refused.

## Validation

New real SQLite and PostgreSQL integration tests cover persistence, repeat initialization, assignees, stale versions, controlled closure, tenant isolation, viewer permissions, explicit preview/send, unavailable transport and uncertain transmission. Vue tests verify inert preview content, read-only restrictions and explicit revision-bound send. Existing investigation, evidence, account, enrichment, retention and backup suites must also pass.
