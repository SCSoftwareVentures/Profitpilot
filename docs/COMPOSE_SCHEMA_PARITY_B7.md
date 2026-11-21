# ProfitPilot B7 — Clean Compose schema parity and release consolidation

**Scope:** Correct and guard a first-initialisation drift between the local Docker Compose schema bootstrap and the CI PostgreSQL migration sequence. This is not a production migration, a customer data operation, or an authorisation to deploy.

## Root cause and correction

At B6 commit 4fe2312859618b5e3f5cc2ddc9d72f00dbac53a7, GitHub CI applied all 32 ordered migration files numbered 002 through 033, while docker-compose.yml bootstrapped only 002 through 024. The nine missing migration files were 025_securepay_evidence_register.sql through 033_securepay_encrypted_custody.sql.

Because a fresh Compose database runs the SQL files under /docker-entrypoint-initdb.d in lexicographic order, a new local installation could lack the tables/policies needed by the later synthetic SecurePay custody and evidence rehearsals, even though CI was green. That is a real build/transfer defect, not merely outdated documentation.

B7 mounts all nine missing migration SQL files under numbered read-only init paths 027 through 035. Earlier bootstrap order is unchanged: schema, runtime role, tenant RLS, private HMAC context key, then subsequent migrations. Existing SQL source files and business logic remain unchanged.

## Automated safeguards

- tests/bootstrap-parity.test.js compares *every* numbered SQL file in database/migrations/ with the Compose first-run mounts and the CI psql migration list. It requires exact same sequence, unique Compose destination ordinals, read-only mounts and correct bootstrap role/key ordering.
- GitHub CI runs this alongside existing Node tests. The existing PostgreSQL job also applies every SQL migration individually and exercises authenticated API, tenant RLS, backups and synthetic recovery.
- The CI Node job additionally performs a non-starting docker compose config --quiet syntax check with dummy example credentials. This does not deploy or boot any service.

## Limitations and warnings

**Existing named PostgreSQL volumes are NOT migrated by adding init mounts.** Docker entrypoint init scripts execute only on first creation of the database directory. To update an existing database, a qualified operator must back it up, apply carefully versioned SQL with a transactional/migration strategy, validate roles, privileges and application behaviour, and rehearse rollback or recovery. Never destroy a real database volume to replay initialisation.

No actual clean Docker Compose startup or upgrade against an existing database is asserted by the static parity test or the config check. Such an end-to-end rehearsal remains a release acceptance task. This branch remains a draft and does not change live customer data, production permissions or legal/payment authority.

## Integration candidate boundary

The current B6 stack has 97 commits ahead of main and 81 changed files, as observed through the GitHub compare endpoint. Seven recent draft PRs (#69–#75) are stacked and mergeable according to the repository API, but that alone does not prove independent acceptance, legal clearance or deployability.

Once B7 passes its own CI, any consolidated main-target PR is for **review only**. Do not merge or publish without explicit owner approval and independent review of migration order, security claims, real device acceptance, IP/licensing, pilot evidence and G0–G5 prerequisites.
