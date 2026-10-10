# Investigation report contract

The saved parser report and original evidence remain unchanged. `GET /api/workspace/analyses/{id}` adds a read-time `result.investigation` projection for both existing and new reports. Every link and count uses the current workspace database; it does not query an external service.

## Identity, routing and body text

`identity` contains `raw_from`, `display_name`, `address`, `domain`, `reply_to` and `return_path`. The latter two are arrays of `{display_name,address,domain}`. The raw From value preserves the display name alongside the normalized address. `anomalies` contains `{code,message}` hints: `reply_to_domain_differs`, `return_path_domain_differs` and `display_name_domain_differs`. These are review prompts, not proof of impersonation; legitimate forwarding, service providers and unrelated names can explain differences.

`routing` contains `{order:"oldest_first",hops:[...]}`. A hop retains the parser's `from_`, `by`, `date`, `delay` and `src` fields. The parser already stores Received headers from oldest to newest; consumers must not reverse this array again. These are message-supplied headers, not independently authenticated routing evidence.

`bodies` contains `{index,content_type,text}` for every body. HTML-only messages have extracted text with script, style, template and noscript elements removed. The original HTML remains in `result.eml.bodies[index].content`; extracted text never replaces it or loads a remote resource. Consumers must escape extracted text and keep HTML isolated using their existing sandbox/CSP.

`authentication.declared` contains `{source,raw,authserv_id,mechanism,result,detail,confidence:"unverified"}` records extracted from Authentication-Results, ARC-Authentication-Results and Received-SPF. SPF, DKIM and DMARC declarations are unverified claims from the message. No DNS lookup runs during parsing or while opening a report.

## URL and attachment context

`urls` contains `value`, `domain`, `display_texts`, `destination_mismatch`, `ioc_id`, `analysis_count`, `case_count`, `campaigns` and `enrichments`. Displayed URL domains that differ from the destination produce a mismatch hint. Literal and parser-normalized URLs may both appear when an email uses a wrapper such as Safe Links. An unindexed literal has `ioc_id:null` and zero counts.

`attachments` contains `index`, `filename`, `sha256`, the same occurrence/campaign/enrichment fields, and `static_findings` associated with that SHA-256. Attachment bytes are never included in this projection.

Counts include the current analysis and all indexed occurrences in this workspace. `campaigns` is a list of `{id,name}` for non-deleted campaigns connected to those occurrences. `enrichments` contains the latest persisted observation per provider and exact target. Provider metadata such as urlscan domain, IP, title, country, score, categories, visibility, redirect observations and screenshot URL stays under the observation's `metadata`; displaying this context does not refresh it or download a screenshot. Full history is available from `GET /analyses/{id}/enrichments?limit=50&offset=0`, which returns `{items,total}` and permits limits from 1 to 200.

## Explicit DKIM verification

An administrator may set `DKIM_LOOKUP_ENABLED=true` in addition to `CONNECTIVITY_MODE=restricted` or `connected`. The default is disabled. Offline or invalid connectivity mode refuses the action before evidence access, result creation or DNS. An embedding application may supply the isolated policy key `dkim.enabled`; a policy factory never falls back to the environment.

`GET /api/workspace/integrations` exposes `dkim:{enabled,allowed,mode}`. An Admin or Analyst explicitly calls `POST /api/workspace/analyses/{id}/dkim` with `{confirm:true,request_id?:UUID}`. The UI must explain that this sends selector/signing-domain DNS names to the configured DNS infrastructure. It sends neither the original message nor attachment bytes to a provider. Reusing a request UUID returns the stored operation without issuing another lookup.

An active operation remains `pending` until its result and audit event commit together, so Cloud retention cannot remove the evidence while verification is running. Only one DKIM operation may be pending per analysis. A crash leaves that operation pending; local result reads never restart verification. After the 60-second recovery deadline in `poll_after`, an Admin or Analyst may explicitly call `POST /analyses/{id}/dkim/{enrichment_id}/recover` with `{confirm:true}`. This marks the operation `unavailable` with reason `verification_interrupted` and an audit event. Recovery works offline, sends no DNS query, is idempotent and refuses an unexpired operation with 409. A late finalizer cannot overwrite a recovered result; if recovered evidence was subsequently purged it receives a safe 410. A new verification requires another explicitly confirmed action and a new request UUID.

Verification reads the SHA-256-checked original bytes. MSG containers return `unavailable` with `original_format_unsupported`: conversion cannot reconstruct the original signed MIME bytes reliably. An EML without a DKIM signature returns `unsigned` without DNS. Current DNS keys may differ from the keys published when an old email was sent.

Cryptographic parsing, canonicalization and RSA calculations run in a separate process. This worker receives no provider, database, SMTP or application encryption secrets and has no DNS client. The authorized parent provides bounded TXT responses through a small pipe protocol. The worker is constrained to 3 seconds of CPU, a 10-second total deadline, 32 file descriptors and, on Linux, 384 MiB address space; it is killed and reaped on timeout or cancellation. The original is limited to 20 MiB, at most five signatures/DNS requests are processed, each DNS call has a two-second timeout, and a TXT key is limited to 4096 bytes. No more than ten actions per minute are admitted in the workspace, and the shared per-analysis enrichment history cap is 1,000. These limits can yield `unavailable` for unusually large or slow but otherwise valid messages.

The result uses the existing enrichment schema:

```json
{
  "provider": "dkim",
  "action": "verify",
  "target": {"kind": "sha256", "value": "original SHA-256"},
  "status": "available",
  "metadata": {
    "verification": "valid",
    "reason_code": "signature_verified",
    "signing_domains": ["example.org"],
    "dns_queries": ["selector._domainkey.example.org"],
    "source_sha256": "original SHA-256"
  }
}
```

`verification` is `valid`, `invalid`, `unsigned` or `unavailable`. Terminal `status` is `unavailable` for incomplete/unavailable checks and otherwise `available`; an active operation has status `pending` and reason `verification_in_progress`. At least one verified signature yields `valid`; this does not assert From-domain alignment, historical DNS authenticity, sender trust or absence of phishing. `malicious` remains null. The result is persisted, timestamped and audited independently of analyst decisions; it never modifies an Authentication-Results declaration.

## Exports and dashboard

JSON, escaped HTML and evidence ZIP reports include the investigation projection and all persisted `enrichments`, including unavailable results and their provenance. JSON retains the source body content; HTML renders its escaped text alongside identity, chronological routing, declared authentication and enrichment observations. HTML provider links are rendered as text, not automatically fetched. Evidence ZIP attachment inclusion remains opt-in by zero-based index: `?attachments=0,2`. No parameter means no attachment payloads.

`GET /api/workspace/dashboard` retains its existing fields and adds:

| Field | Meaning |
| --- | --- |
| `pending_verdicts` | Completed analyses with no decision or a latest reopened decision |
| `active_campaigns` | Active, non-deleted campaign count |
| `frequent_iocs` | Top ten `{id,kind,value,analysis_count,case_count}` records by analysis occurrence count |
| `recent_analyses` | Latest ten `{id,case_id,filename,subject,status,created_at}` records |

## Safe analysis failures

New worker failures persist a finite code with a safe message in the existing `error` field. Analysis details additionally expose `error_code`; historical unclassified errors return null. Codes are `parser_timeout`, `resource_limit`, `parser_rejected`, `report_limit`, `evidence_unavailable`, `evidence_integrity`, `storage_unavailable` and `analysis_failed`. The worker does not expose exception strings, source bytes, parser output, local paths or credentials. Failed parsing preserves the original and follows the existing retry policy; integrity failures require investigating storage before retrying.

## Verification

`tests_workspace/test_report_context.py` uses real MIME parsing and persisted investigation records to exercise identity, chronological routing, HTML-only text, auth declarations, related IOC/campaign counts, enrichment exports, dashboard decision/reopening counts and safe job failures. `tests_workspace/test_dkim_api.py` signs a real message with a generated RSA key and verifies it in the real subprocess against injected DNS TXT responses. It covers offline/flag/tenant policy, roles/CSRF, idempotency, invalid/unsigned/unavailable results, evidence integrity, DNS bounds, actual deadline termination/reaping, operating-system CPU limits, active-operation protection and explicit recovery with a late-result fence. The memory-limit regression runs on Linux. No live DNS query or provider call is needed for these tests.
