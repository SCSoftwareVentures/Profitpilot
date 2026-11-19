# ProfitPilot — Field Knowledge Memory

**Capability:** sixth approved differentiator  
**Implementation stage:** synthetic, in-memory, permission-aware knowledge ledger  
**Status:** prototype only; not a production knowledge store

## Purpose

Preserve useful, permissioned operational knowledge so a cleaning business does not repeatedly rediscover site requirements, scope clarifications, equipment constraints and proven issue resolutions.

## Implemented

- Typed knowledge categories for site requirements, scope clarifications, equipment constraints, recurring issues, resolutions, safety references and customer preferences.
- Tenant-bound records with stable item IDs, event IDs and immutable version history.
- Required owner, source reference, permission reference, source date and review date.
- Optional evidence reference, expiry date and explicit confidence state.
- Visibility levels: tenant, site team and owner/admin.
- Site-team access filtered against the actor's assigned site IDs.
- Restricted knowledge requires owner/admin visibility.
- Authentication secrets, access codes and selected financial identifiers are rejected.
- Verified knowledge requires an evidence reference.
- Append-only corrections with actor, timestamp, reason and prior-version reference.
- Dynamic stale, expired and conflicting status assessment.
- Tenant- and role-filtered search.
- Synthetic mobile-friendly demonstration.

## Integrity and privacy rules

- A record is not authoritative merely because it was used before.
- Stale and conflicting instructions remain visible for review; the engine does not silently select a winner.
- A version change creates a new snapshot; old versions are retained.
- Site-team visibility does not grant access to another site.
- Owner/admin-only records are not exposed to ordinary site staff.
- The prototype is not a credential vault. Do not store passwords, door codes, alarm codes, API keys, bank details, tax identifiers or other secrets.
- No real customer, employee, access or confidential business data belongs in this public repository or demonstration.

## Known limitations

- In-memory only; no database persistence, API, full-text search service or tenant identity-provider integration.
- Actor roles and site assignments are synthetic claims supplied to the domain function; production authorization must be enforced by the authenticated server and database.
- No attachments, malware scanning, retention/deletion scheduler, notifications or offline synchronization.
- No AI extraction or retrieval; all content and status transitions are explicit.
- No customer validation or measured time-saving evidence.

## Acceptance evidence

Tests cover provenance, permission references, verified-evidence requirements, secret rejection, tenant isolation, site scoping, owner/admin visibility, version chronology, append-only history, stale/expired/conflict detection and search filtering.

## Definition of done for this stage

Synthetic knowledge records can be created, versioned, searched and assessed without persistence; stale and conflicting knowledge is surfaced; tenant/site/role visibility rules are test-covered; limitations are explicit.
