# Community enrichments

PhishCase analyses remain usable without provider credentials. External enrichment is an explicit analyst action on an existing analysis. A missing report is an **unknown result**, never an instruction to upload evidence. Provider observations do not modify the original email, attachment bytes or an analyst verdict.

The ingestion parser always uses a local-only policy, including when the server is in `restricted` or `connected` mode and lookup flags are enabled. It instantiates no VirusTotal, urlscan or EmailRep client and performs no DKIM DNS lookup. Only loopback SpamAssassin and static parsing run at ingestion. Provider permissions enable the explicit enrichment endpoints below; they never enable automatic calls from parsing or retries. Those endpoints enforce target selection, permissions, persisted request budgets and audit trails.

The contract from draft PR #1 (`feature/v2-investigation-foundations`) was reviewed and adapted; the draft was not merged. Its policy, target, result, lookup and submit interfaces and four policy tests are retained, with `poll`, `normalize`, `healthcheck`, persistent results and concrete providers added.

## Configuration and sharing

Configure these values in the server environment (or a deployment secret manager that injects environment variables). Restart the application after changing them. Never commit credentials, place them in browser settings, or add them to URLs.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CONNECTIVITY_MODE` | `offline` | `offline`, `restricted` or `connected`; invalid values fail closed |
| `VIRUSTOTAL_API_KEY` | empty | Administrator's licensed BYOK/BYOL key |
| `URLSCAN_API_KEY` | empty | Administrator's urlscan key |
| `VIRUSTOTAL_LOOKUP_ENABLED` | `true` | Allows read operations only when mode permits |
| `URLSCAN_LOOKUP_ENABLED` | `true` | Allows read operations only when mode permits |
| `DKIM_LOOKUP_ENABLED` | `false` | Allows the separate, explicitly confirmed DKIM DNS verification action when mode permits |
| `VIRUSTOTAL_ALLOW_FILE_SUBMISSION` | `false` | Separate connected-mode authorization for attachment uploads |
| `VIRUSTOTAL_ALLOW_URL_SUBMISSION` | `false` | Separate connected-mode authorization for scanning URLs |
| `URLSCAN_ALLOW_URL_SUBMISSION` | `false` | Separate connected-mode authorization for scanning URLs |

`offline` blocks lookups, submissions, polls and remote health checks before a provider is instantiated. Reading local results and integration status remains available. `restricted` permits lookups and polling only. `connected` additionally permits individually enabled submission kinds. Having a key or a lookup permission never enables submission by itself.

Community has one administrative scope and a shared team; this policy is not multi-tenant isolation. Admin/analyst roles may request enabled operations; viewers only read results. Health checks require Admin. Session writes retain the application's CSRF header; API tokens use the same role checks.

Lookup exposes the selected hash, URL, domain or IP to the configured provider. File lookup sends the SHA-256, not attachment bytes. URL lookup sends the URL (which can contain sensitive query parameters). Submission additionally sends the selected attachment bytes or asks the provider to visit the extracted URL. There is no arbitrary local URL fetch, browser navigation, automatic submission on a miss, provider retry or fallback from private to public.

VirusTotal uses its standard API. This implementation does **not** use VirusTotal Private Scanning and cannot promise confidential handling of submitted files or URLs. The administrator must verify that the key's licence permits their intended commercial use; a configured key or successful health check does not certify that licence. Do not assume a free key permits commercial SaaS use.

urlscan submission always includes visibility explicitly. The default is `private`; an analyst may explicitly choose `unlisted` or `public`. If the plan rejects private scans, the action fails and never silently retries at another visibility. A returned visibility mismatch is stored as an error with the accepted scan ID for investigation. Unlisted is not equivalent to private. Remote deletion of an accidental submission is not implemented.

Keys remain in the process environment, outside the investigation database. API responses return only configuration booleans. There is no key-editing browser form, key export or encrypted credential database in this Community implementation. Use a host secret manager and restrict process/container administrator access. Credential rotation currently requires a service restart.

## Provider behavior

| Provider | Lookup | Submit | Poll |
| --- | --- | --- | --- |
| VirusTotal | SHA-256, URL, domain, IP report | Stored attachment (20 MiB maximum), extracted URL | Stored VT analysis ID |
| urlscan | Latest existing scan for exact URL/domain or IP search, then its report | Extracted URL with explicit visibility | Stored scan UUID |

All HTTP destinations are constants: `https://www.virustotal.com` and `https://urlscan.io`. Target strings and returned provider links cannot select an HTTP origin. The adapters disable redirects, environment proxies and retries, use a 15-second total deadline (including streamed body reads), and limit decoded JSON bodies to 2 MiB. Errors use fixed codes and discard provider response bodies and exception strings. No HTML, DOM, screenshot, favicon or scanned website is downloaded by the backend. Provider report links and screenshot links are generated from validated IDs; the UI must keep any screenshot loading explicit and escape all textual metadata.

VirusTotal's normalized observations include malicious, suspicious, harmless and undetected (`unknown`) counts, first submission time, file type, bounded detection labels and a provider link when a valid canonical identifier is available. Missing counts remain `null`, not zero.

urlscan observations include domain, IP, page title, country, score/categories, visibility, a screenshot URL and a partial redirect trace. `redirect_chain_complete` is always false: task/final URLs and available document redirect records are observations, not proof that every hop was captured. The fixed screenshot URL may be unavailable or require provider authentication; PhishCase does not proxy private screenshots or claim screenshot availability. A non-malicious or missing verdict is not proof of safety.

Remote health checks are explicit: VT looks up the known benign empty-file SHA-256; urlscan reads `/user/quotas/`. They consume a provider request. The API returns a sanitized status only, not account/quota payloads. Local status never performs a health check automatically.

## API

Routes are under `/api/workspace`:

| Method and route | Permission | Behavior |
| --- | --- | --- |
| `GET /integrations` | User | Mode and providers with `configured`, `lookup_allowed`, `lookup_kinds`, `submission_allowed`, `secret_source`, optional last health status |
| `POST /integrations/{provider}/health` | Admin | Explicit policy-gated remote check |
| `GET /analyses/{id}/enrichments` | User | Newest-first `{items,total}`; `limit` 1–200, `offset`; `latest=true` selects latest per provider/kind/value |
| `POST /analyses/{id}/enrichments/lookup` | Writer | `{provider,kind,value}`; target must occur in the analysis evidence |
| `POST /analyses/{id}/enrichments/submit` | Writer | `{provider,kind,confirm:true,attachment_index? ,value?,visibility?,request_id?}` |
| `POST /analyses/{id}/enrichments/{enrichment_id}/poll` | Writer | Polls the stored provider/job for this exact analysis; caller cannot supply a job URL or ID |
| `POST /analyses/{id}/dkim` | Writer | Explicit `{confirm:true,request_id?}` verification against checked original bytes, separately gated by DKIM policy |
| `POST /analyses/{id}/dkim/{enrichment_id}/recover` | Writer | Explicit `{confirm:true}` closure of an interrupted DKIM operation after its recovery deadline; local-only, no DNS/retry |

File submission selects only a zero-based attachment index. URL submission selects only a URL extracted from the email. Analyst-added case IOCs do not grant permission to send arbitrary values. Attachment bytes are rechecked against their stored SHA-256. Missing analyses, missing/tampered evidence, unsupported target kinds and incompatible fields are refused before network access.

An item has `id`, `analysis_id`, `action`, `provider`, `target: {kind,value}`, `status`, `malicious`, `suspicious`, `harmless`, `unknown`, `summary`, `external_id`, `external_url`, `first_seen`, `file_type`, bounded `metadata`, UTC `created_at`/`updated_at` and epoch `poll_after`. Status is one of `available`, `unknown`, `unavailable`, `pending`, `error`. No raw provider object or credential is returned or stored.

Submit accepts an optional client-generated UUID `request_id`. Reusing it with the same request returns the persisted operation; reusing it for a different request returns 409. Concurrent pending submissions for the same analysis/provider/target are refused even without a key. Generate one UUID per explicit user action and reuse it only when recovering that action's response.

Provider requests reserve a database-backed shared rate slot: 4 operations/minute for VT and 10/minute for urlscan (a urlscan search hit makes two HTTP GETs). Failures and health checks count; provider 429 responses are not retried. Polls are spaced at least 30 seconds apart and limited to 40 attempts per result. There is no background polling. Each analysis retains at most 1,000 enrichment operations. These conservative limits are local safety limits, not a claim about a subscription's actual quotas.

State is persisted before an external request. A network timeout or process crash during submission can leave uncertain acceptance: inspect the provider before creating another submission. Pending operations without a returned external ID cannot be polled automatically. The operation/event history is retained for review; the application does not silently replay outbound uploads after restart.

## Validation and limitations

`tests_workspace/test_enrichment*.py` covers the draft policy contract, fixed HTTP protocols, no upload on lookup miss, offline behavior, role/CSRF checks, evidence binding, integrity validation, error redaction, visibility defaults, idempotency, persistence, rate/poll limits, response-size and total-time limits. All provider tests inject mocks; no real credentials, scans or external uploads were used. Live account entitlements, provider availability and production quotas remain deployment checks performed explicitly with the operator's own key.

The contract is extensible; MISP, OpenCTI, AbuseIPDB and additional sandbox integrations are not implemented. Community does not supply tenant-specific credentials or policies. Enterprise must provide isolated scope and governance when it composes these capabilities.

See [Investigation report contract](INVESTIGATION_REPORT.md) for identity and URL/attachment context, persisted enrichment exports, and the separate DKIM action. DKIM DNS checks use an isolated cryptographic process with explicit time/CPU/memory bounds; a valid signature is never treated as a phishing verdict. Ingestion and report reads remain local-only.

Protocols were checked against the official documentation on 2026-09-23: [VT file reports](https://docs.virustotal.com/reference/file-info), [VT file upload](https://docs.virustotal.com/reference/files-scan), [VT URL identifiers](https://docs.virustotal.com/reference/url), [VT URL submission](https://docs.virustotal.com/reference/scan-url), [VT analysis polling](https://docs.virustotal.com/reference/analysis), [urlscan API](https://urlscan.io/docs/api/), [urlscan search](https://urlscan.io/docs/search/) and [urlscan result schema](https://urlscan.io/docs/result/).
