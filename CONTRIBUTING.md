# Contributing / Contribuer

Community changes belong in this public MIT repository; commercial adapters belong
in the private Enterprise repository. Preserve the original eml_analyzer attribution
and LICENSE. Do not copy commercial code or secrets into a Community pull request.

Start from a topic branch, use synthetic fixtures, and explain behavior changes and
validation in your PR. Keep APIs compatible or document the migration. Database
changes require an idempotent, versioned upgrade and a backup/restore exercise.
Tenant-aware adapters must pass their private isolation suite after every core update.

Install Python 3.14, Node 24, libmagic and uv. Run:

```sh
uv sync --frozen
uv run ruff check backend tests tests_workspace
uv run python -m pytest tests_workspace
cd frontend
npm ci
npm run type-check
npm run test:unit -- --run
npm run build
```

Historical engine tests in `tests/` require local SpamAssassin. New provider tests
must simulate transport and assert offline/submission boundaries. Never send real
emails or attachments during CI. Live provider checks are separate operator tasks
requiring appropriate keys and licences. Report test warnings and exclusions honestly.

No merge or release is implied by opening a PR. Draft PR #1 remains subject to
review; this release candidate reuses its provider-contract ideas without merging it.

En français : petites modifications relisibles, preuves synthétiques et tests utiles.
Documentez toute migration ; signalez les vulnérabilités selon SECURITY.md.
