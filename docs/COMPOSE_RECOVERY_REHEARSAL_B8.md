# ProfitPilot B8 — Synthetic Docker Compose startup and historical-volume upgrade rehearsal

**Scope and safety:** CI-only, disposable synthetic PostgreSQL databases, not a production deployment or a general-purpose migrator. Uses only temporary Docker Compose project names, ephemeral runner volumes, random credentials and fabricated tenant records. The CI job deletes its own volumes on exit. Never point it at a real database or run it on an owner's device.

## Reason for this milestone

B7 found that PostgreSQL CI applied all 32 migrations (002–033), while a first-time Compose bootstrap had omitted nine SecurePay migrations (025–033). B7 brought the two file lists into parity, but static tests and configuration validation could not establish actual Docker Compose startup and existing-volume behaviour. B8 exercises these scenarios on a hosted GitHub runner without adding infrastructure or touching real business records.

## Automated phases (only successful when the B8 job passes)

1. **Clean current Compose boot.** Bring up only the database service on an isolated named volume. Wait until its health check and final encrypted-custody table both exist; confirm the private signing-key table and runtime role without elevated superuser/BYPASSRLS rights.
2. **Historical fixture.** Derive a temporary, local-only previous-generation Compose configuration by removing exactly the nine migration mounts numbered 025–033. Start a fresh isolated legacy database and verify the late SecurePay tables are absent. Insert one explicitly synthetic tenant marker.
3. **Backup and restoration before migration.** Create an encrypted AES-256 custom-format PostgreSQL archive with a random ephemeral passphrase. Reject decryption with the wrong key. Decrypt and restore into a separate synthetic test database. Verify the tenant marker survived.
4. **Existing-volume preservation.** Switch back to current Compose against the same named volume. Confirm the synthetic tenant remains and the newer schema is *still absent*: Docker's entrypoint never silently applies fresh init scripts to an existing database.
5. **Manual schema upgrade.** As a CI-only controlled simulation, execute the actual 025–033 SQL migrations in order against that backed-up existing database. Verify the latest table and original synthetic data survive. Restart the database; confirm schema and marker persist and that an unscoped runtime-role query sees zero tenants.

On failure the script exits nonzero and CI fails. It does not hide skipped steps or copy private credentials into a public artifact. The script refuses execution unless GitHub CI environment markers are present, and all database resources belong to a purpose-generated Compose project that is removed after testing.

## Evidence requirements and limitations

The GitHub job **Synthetic Compose boot and legacy-volume upgrade** is a new release gate. Existing CI packaging and source-provenance jobs depend on its success. Static Node.js tests separately check that the synthetic legacy fixture has exactly 23 migration mounts (rather than 32), that CI gating remains present and that the shell procedure is CI-only. Shell syntax is checked in npm run check.

The test may pass while production remains unready: the scenario uses a single fabricated tenant marker, no customer exports, no real deployment credentials, no real identity provider and no private back-up vault. It is **not** proof that every possible historic schema or actual customer-volume upgrade can be performed safely. The rehearsal demonstrates only the particular pre-B7 schema boundary and the tested migration chain.

## Actual upgrade requirements (not implemented as an automatic user action)

Before any real upgrade, an authorised administrator must verify the deployed application and database versions, take a protected backup, independently test a restore, establish a maintenance window and a rollback/recovery decision, reconcile previous custom migrations and production data, arrange qualified review of SQL privileges/policies and data retention, and supervise a staged migration. Do not use docker compose down --volumes on a real environment. Do not assume replaying the CI shell procedure is an approved production operation.

The current proposal remains in a draft branch. **No production migration, external hosting, payment enablement, provider integration, actual customer testing or authorisation for sale has occurred.** The G0–G5, IP, buyer-demand and physical iPhone acceptance gates remain open.
