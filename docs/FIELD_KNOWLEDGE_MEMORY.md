# ProfitPilot — Field Knowledge Memory

**Capability:** sixth approved differentiator  
**Implementation stage:** deterministic in-memory domain model and permission-filtered retrieval  
**Status:** prototype only; no database persistence, authenticated API, encryption-at-rest or production access-control integration

## Implemented in this slice

- Explicit knowledge classes: verified instruction, customer preference, observation, suggestion and unverified note.
- Required source provenance, owner, confidence, scope, visibility, review date and optional expiry.
- Verified instructions require an evidence reference, reviewer and confirmed review outcome.
- Private, site and team visibility scopes.
- Retrieval requires an explicit tenant, actor, site and team access context; missing context returns no results.
- Tenant, site, team and private-owner filtering is applied before text matching.
- Stale, expired, rejected and unreviewed knowledge is not surfaced as current reviewed knowledge.
- Reviews append events and immutable versions; rejection retains history while removing the item from retrieval.
- Retrieved knowledge is not an automatic instruction or safety/compliance approval.

## Safety boundaries

This is a pure in-memory domain model. It does not persist data, authenticate users, prove that caller-supplied access context is genuine, encrypt content, manage consent, or enforce retention/deletion. Those controls must be implemented at the authenticated service and storage layers before any real site, access, customer or employee information is entered. Do not treat this prototype as a security boundary.

## Acceptance coverage

Automated tests cover provenance requirements, visibility scope, tenant/site/team/owner isolation, stale and expired suppression, review/version history, rejection, chronology, duplicate event IDs and fail-closed retrieval without access context.

## Remaining work

- Tenant-scoped database schema, forced RLS and immutable event/version persistence.
- Authenticated API integration using server-derived permissions, never client-supplied authority.
- Encryption, retention/deletion, consent and privacy classification.
- Conflict/staleness review queues, searchable indexing and auditable correction workflow.
- Mobile UX and synthetic end-to-end demonstration.
