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

## Early completion checkpoint — 2026-09-23

The new investigation/report/DKIM regression suite and existing workspace suite passed on macOS: **114 tests and 30 subtests**, with the Linux-specific address-space limit check skipped on macOS. The new DKIM checks use a real isolated cryptographic process and injected synthetic DNS, including CPU and deadline termination. No external DNS/provider was queried. The Community frontend passed **71 tests**, TypeScript and build after the dashboard, structured observations, package selection and pagination updates. A subsequent Linux CI/container run is required for the memory-limit assertion and historical engine tests. These are functional/regression checks, not a replacement of the revision-specific security reports.

## Completed investigation checkpoint — 2026-09-23

At `d5a5ea3c7f9296964ac3f2735d5fed74c10c6b1e`, all three GitHub workflows passed. Linux backend results were **158 passed, 102 subtests passed, one optional historical skip**; the real DKIM address-space limit, CPU and deadline checks passed. Frontend results were **72 tests across 23 files**, with TypeScript, lint and production build passing. These results supersede the earlier pending-Linux note above.

The final disposable browser walkthrough uploaded **both EML and MSG through the actual file chooser**, observed completed jobs, sender identity/routing/context, English persistence, campaign-query persistence after reload and dashboard counts. Unlike the earlier browser checkpoint, this upload succeeded. A selected-attachment ZIP download was triggered in the browser. A separately authenticated API download was then inspected: exactly original, JSON report, selected attachment and manifest; every hash/size matched and the unselected attachment payload was absent. SpamAssassin was explicitly disabled only in this disposable test; provider and DNS traffic stayed disabled. The later interrupted-DKIM recovery button was covered by component tests/build rather than another full browser walkthrough.

Private PostgreSQL composition and production HTTPS validation are recorded in the Enterprise validation record. The latest branch additionally improves localized error fallbacks, branding and storage readiness; their regression tests run in the same mandatory workflows. No new security-scan attestation is implied.
