# Release candidate validation — 2026-09-23

This is a validation record for the candidate branch, not a stable-release claim.

| Check | Observed result |
| --- | --- |
| Combined Community backend and historical engines | 144 tests passed; 1 upstream optional test skipped; 98 subtests passed. Includes >500 pagination, bounded legacy lists, strictly local parsing, provider identity/decompression bounds, queue leases/retries, immutable evidence, MFA, roles, uploads and exports |
| Community frontend | 64 unit tests passed; TypeScript, targeted ESLint and production build passed on Node 24 |
| Python static checks | Ruff and git diff whitespace checks passed |
| Dependency advisory check | pip-audit found no known vulnerabilities in locked PyPI runtime dependencies. The pinned Git-only MSG converter is not covered by PyPI advisory matching |
| Docker build | Candidate image built from frozen dependencies; MIT notice included |
| Docker runtime | Fresh isolated volume; upload 202 → worker completed; SpamAssassin and OLE present; original bytes identical; readiness 200 |
| Browser walkthrough | Login, cases, campaigns, notes, global search, direct URLs, back/forward, FR/EN persistence, report, human verdict/reopen and disabled offline integrations verified |
| Encrypted backup | Real SQLite snapshot/restore preserves original and queued job; modified archives and unsafe paths rejected |
| VPS | Plesk/Docker/Compose, free ports/storage and dedicated SSH access verified; no application deployment validated at this checkpoint |

Browser file selection was blocked by the automation upload permission gate. The
browser report walkthrough used a separately generated synthetic message uploaded
through the normal API testing workflow. Do not describe this as browser-upload E2E.

Dependency warnings remain in oletools/pyparsing and the legacy MSG compoundfiles
stream finalizer. They did not fail assertions; they are not silently removed from
logs. Live VirusTotal/urlscan service and licensing checks were not performed: no
production provider key was used. Transport tests are simulated.

The initial security audit applied to pre-change commit d9c2860 and cannot certify
this candidate. A review of the candidate diff and private Cloud isolation/billing
suite is separate. Cloud results belong in the private repository. Public signup,
transactional email, Stripe checkout, TLS and backup restore on the VPS must be
verified before declaring a production release.
