# Emails and optional campaigns

Upload preserves an independent email. It never creates a case or campaign. Its original, attachments, analysis, enrichments, analyst verdict, decision history and reporter replies remain attached to its analysis UUID. Campaigns are optional, many-to-many collections of emails for collective follow-up: owner, priority, status, tags, description, notes, actions, intelligence and timeline. Detaching an email does not delete or change its evidence or verdict.

Reception keeps immediate upload and presents recent emails, analyses to review, campaigns to follow and frequent IoC. The primary navigation is Reception, Emails, IoC, Campaigns and Actions. Use Emails to select messages and create a campaign or link them to an existing campaign. Assignment organizes work; all active members retain their role-based team permissions.

## Canonical API

Both Community prefixes `/api/v1` and `/api/workspace` expose the contract. Cloud uses `/api/workspace` with server-selected organization scope. Analyst/admin writes require the normal token or CSRF-protected session; viewers can read.

| Route | Contract |
| --- | --- |
| `POST /analyses` | Multipart EML/MSG; 202, independent analysis UUID; original limits and idempotency apply |
| `GET /campaigns` | Paginated search, status, tag and `scope=mine|team` |
| `POST /campaigns` | Name, optional description/tags/priority/owner/status and `analysis_ids`; owner defaults to creator unless explicitly null |
| `PUT /campaigns/{id}` | Update with the `revision` read; stale revisions return 409 |
| `POST /campaigns/{id}/emails` | `{ "analysis_ids": ["uuid"], "revision": 1 }`; validates all IDs atomically |
| `DELETE /campaigns/{id}/emails/{analysis_id}?revision=…` | Removes only this relationship; refuses a stale revision |
| `GET /campaigns/{id}/emails` | Paginated members |
| `GET /analyses/{id}/campaigns` | Active campaign relationships |
| `GET /campaigns/{id}/iocs` | Extracted IoC from member emails with email occurrence counts |
| `GET/POST /campaigns/{id}/notes` | Append-only notes with author and time |
| `GET /campaigns/{id}/events` | Campaign events and events of member emails |
| `GET/POST /campaigns/{id}/actions` | Collective follow-up; action updates retain revisions and mandatory completion/cancellation proof |
| `GET/POST /analyses/{id}/actions` | Follow-up on an independent email |
| `GET/POST /analyses/{id}/replies` | Reporter drafts attached to the email; preview, explicit send and reconciliation remain version-bound |
| `GET/POST /campaigns/{id}/replies` | Collective drafts and member email replies |
| `DELETE /campaigns/{id}?revision=…` | Soft archive; preserves relationships/history/evidence and verifies outstanding work |
| `GET /legacy/cases/{id}` | Historical mapping and canonical URL for old links |

Closing a campaign requires no collective pending action, no queued/running member, an active analyst decision on each completed member and no related reply still transmitting. Failed analyses remain visible for review. Reopening a member decision reopens its campaigns for investigation. Replies are never sent merely by attaching an email or changing a campaign.

## Conservative migration

SQLite version `2026101002` runs under the initialization lock. The NOT NULL constraint on `analyses.case_id`, actions and replies is removed by a transactional table rebuild retaining all columns and explicit indexes. Foreign keys are verified before commit. New records use `campaign_analyses`, `campaign_notes`, campaign metadata, explicit action/reply scope, and `events.analysis_id`.

The projection recognizes an automatic case only when it contains exactly one email, its title matches the recorded automatic title or the exact generated date/subject title, its status/priority/owner/revision remain initial, and it has no description, note, collective action/reply or intelligence context. That email stays independent unless an existing campaign already groups it. Other cases become campaigns preserving title, description, status, priority, owner, revisions and timestamps. Notes preserve author/time and original note ID. Actions, collective replies, intelligence, memberships and events are projected without deleting their historical records. Email-specific replies, decisions, originals, attachments and reports retain their IDs and contents.

`legacy_case_links` records every conversion. Existing case rows, notes and `campaign_cases` are retained as an archive for traceability and deprecated client compatibility; the product no longer creates or navigates cases. New integrations must use the canonical routes above. Repeated initialization does not duplicate migrated records. Existing numeric campaign IDs remain stable; email-to-campaign relations allow multiple memberships.

Stop app and worker, create an encrypted database/evidence/key backup, verify restoration to an empty isolated target, and migrate that copy before production. Verify row conservation, proof hashes, relationships, legacy mappings, permissions and concurrency. Whole-database backups include the new tables automatically. Restoring a published Folio snapshot and starting this version reruns the migration conservatively.

An old image cannot safely read newly independent emails. Do not roll back only the image after new writes; preserve the current data and deploy a compatible repair, or restore a verified backup into another stack and reconcile subsequent writes before switching.

En français : les emails restent autonomes ; une campagne organise une investigation collective. L’import n’instancie aucun dossier. Les dossiers historiques sans contexte deviennent des emails indépendants ; leur contexte utile est conservé dans des campagnes, avec des liens de traçabilité.
