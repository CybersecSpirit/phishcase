# API v1 / Ingestion

Community exposes the same authenticated investigation contract at `/api/v1` and
`/api/workspace` (the browser compatibility prefix). User accounts, roles and MFA
use the latter. Cookie-authenticated writes require `X-Requested-With: PhishCase`.
No cross-origin origins are enabled. Cloud identity and billing use a separate
private adapter; use its documentation rather than Community account endpoints.

Create an API token with an authenticated writer session:
`POST /api/v1/auth/tokens` with `{"name":"collector","days":30}`. The token is shown
once and stored as a hash. Pass `Authorization: Bearer <token>`; tokens inherit
the current owner's role and are revoked when the owner is disabled or their
authentication is reset. List or revoke only your own tokens. Expiry is at most
365 days. Keep tokens in a secret store, never command history or URLs.

`POST /api/v1/analyses` accepts multipart field `file` containing EML/MSG, maximum
20 MiB. `POST /api/v1/cases/{id}/analyses` attaches to an existing case. The 202
response contains the analysis ID and queued state. An optional `Idempotency-Key`
(1–128 characters) deduplicates retries for the same owner, content and case;
reuse with different content returns 409. Ingestion is recorded as `api` for tokens
and `upload` for browser sessions. V1 has no inbound mailbox or email add-in.

Poll `GET /api/v1/analyses/{id}` until `completed` or `failed`. The original remains
available at `/source`; attachments at `/attachments/{index}`. Export with
`/export.json`, `/export.html?locale=fr`, or `/evidence.zip?attachments=0,2` appended
to the analysis URL. Omit attachments to include none in the evidence package.
`POST /analyses/{id}/retry` retries only failed jobs.

Lists support `page` and `page_size` and return
`{"items":[],"total":0,"page":1,"page_size":50,"pages":0}`. Exact page-size
bounds are returned by validation errors. Follow server totals, not a fixed ceiling.
Filters/search are bound SQL parameters, never query fragments. When `page`,
`page_size` and `limit` are all omitted, lists retain the earlier array format only up to 500 matching items. Above that boundary the server returns 422 with an instruction to use `page=1&page_size=50`; it never silently truncates or loads the complete legacy result. Pagination totals and subsequent pages remain exhaustive.

Responses distinguish 401 (authentication), 403 (role/policy), 404 (missing object),
409 (state or idempotency conflict), 413 (body limit), 422 (input validation), and
429 (rate limit, respect Retry-After). Community allows 300 authenticated requests
and 20 uploads per user per minute. Provider requests have separate conservative
limits. A network retry never implies permission to submit a file externally.

En français : l’envoi renvoie rapidement un identifiant ; le worker continue hors
du navigateur. Un état « completed » indique un traitement terminé, pas un message
sûr. Le verdict humain et ses justifications restent distincts des signaux moteurs.
