# Security policy

## System and scope

PhishCase Community handles deliberately untrusted EML/MSG files for one security
team. The application, parser, dependencies, worker, storage, browser UI, exports,
provider clients and deployment configuration are in scope. The private Enterprise
adapter has additional identity, tenant isolation and billing responsibilities.
No audit badge or certification is implied by this policy.

## Threat model and trust boundaries

Email content, filenames, MIME structures, archive metadata, URLs, headers,
Authentication-Results, provider responses and API parameters are attacker controlled.
An authenticated analyst may upload malicious samples; viewers may only read.
Host and Docker administrators can access the deployment and are trusted operators.
Original evidence, authentication material, provider keys and audit history are assets.
The UI must not load remote message content or execute attachment code.

## Security invariants

- Authenticate all investigation reads, downloads and changes; enforce current roles
  server-side. Tokens inherit the current user's permissions and expire/revoke.
- Keep cookie writes CSRF-protected; hash passwords, sessions and recovery codes;
  encrypt TOTP secrets, reject replay and revoke obsolete sessions.
- Bound request bodies, parser runtime/memory, MIME complexity and archive expansion.
  A parser failure must preserve the original and cannot block the HTTP process.
- Preserve original bytes, provenance and SHA-256; prevent traversal and symlink
  reads; downloads use attachment, nosniff and no-store response headers.
- Render message HTML inertly, neutralize indicators and escape exported HTML.
  Never fetch a URL supplied by a message from the application server.
- Offline means no optional external analysis/DNS lookup. Restricted permits
  lookups only. Submission requires connected mode, provider/type authorization
  and an explicit analyst action. Keys alone never authorize transmission.
- Keep engine observations, provider coverage and human decisions separate. Missing
  detections or incomplete coverage cannot be presented as proof of safety.
- Do not log passwords, TOTP, tokens, credentials, full messages or attachment bytes.

## Reportable findings and severity

Report reachable violations of these boundaries, including authenticated attacks,
resource exhaustion, unauthorized downloads or changes, script execution, SSRF,
credential disclosure and silent provider submissions. Severity depends on demonstrated
reachability, required role, exposed deployment and concrete impact. A container or
passing test alone does not dismiss a finding. Dependency vulnerabilities require
impact assessment; they are not excluded merely because code is upstream.

## Limitations and unresolved decisions

Community intentionally gives all active team members read access to all team
evidence; assignment is not an access-control list. It is not a tenant-isolation
product. Filesystem evidence is not application-encrypted at rest. The bounded
parser subprocess is not a malware detonation sandbox. Advanced SSO/passkeys,
archive detonation and inbound mail ingestion are not implemented here.
These functional boundaries do not authorize suppressing flaws in promised controls.
No additional finding classes or accepted risks have been excluded by the owner.

Use private vulnerability reporting at
https://github.com/CybersecSpirit/phishcase/security/advisories/new when available.
If unavailable, contact the maintainer via the repository profile without disclosing
exploit details or user evidence publicly. A dedicated security contact and supported
release policy still require owner confirmation before a stable release.

En français : tous les emails et indicateurs sont non fiables. Signalez les failles
en privé ; ne publiez ni échantillons confidentiels ni secrets dans une issue.
