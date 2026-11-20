# Invoice identity and evidence control — proposed validation specification

Status: proposed; not implemented or verified. No G5 build approval implied.

## Observed gaps
The original-file endpoint checks SHA-256 and seals rows; the CSV parser rejects repeated trimmed invoice IDs within one file. The legacy JSON endpoint accepts row objects and the structural validator does not enforce duplicate IDs. Batch locking does not serialize separate batches. File identity is not invoice identity. Existing CSV schema contains invoice_id, site, date, amount but no stable issuer/account identity or currency; invoice numbers alone cannot safely identify supplier invoices across issuers.

## Proposed controls
- Preserve original rows and receipts; never silently delete duplicates or mutate evidence.
- Establish a tenant-scoped identity namespace with direction, stable issuer/account identifier and invoice reference; treat missing issuer identity as unresolved, not as proof of uniqueness. Confirm normalisation rules with source owners. Do not silently fold case or strip leading zeros.
- Link every candidate to tenant, batch, raw row and receipt if present. Distinguish client-declared from byte-verified and issuer-authenticated evidence.
- Hold ambiguous repeat references for human review. Exact file replay remains idempotent; identical economic evidence in different files is not automatically additive. Corrections and credit notes require explicit lineage and approved treatment.
- Before confirmed financial inclusion, use database-enforced uniqueness for the approved canonical identity, plus transactional locking and same-tenant foreign keys; concurrent confirmation must not double count. Preserve competing candidate rows and reviewer reasons in the audit trail.
- Existing records require conflict inventory and explicit migration review; never retroactively claim confirmation or issuer authentication.

## Acceptance tests (not run)
1. Exact byte replay; changed file with same invoice; whitespace variants and leading zeros.
2. Same invoice number from different supplier issuers; same reference in different tenants or directions; missing issuer held.
3. JSON chunk duplicate, original-file/JSON overlap, simultaneous confirmations, atomic rollback on conflict.
4. Correction or credit-note lineage; no duplicate contribution to calculation snapshots; deterministic results on retry.
5. Cross-tenant evidence linkage denied; analyst cannot confirm; reviewer decision and immutable source lineage retained.
6. Migration conflict report, clean install and upgrade path, legacy rows not silently upgraded.

## Blockers
Migration 011 CI and latest invoice fixture correction have no confirmed results in the available connector. Verify push-triggered CI separately. Obtain authorised representative exports under G0 and verify issuer/reference semantics before schema enforcement. Production build remains gated by G0–G5.
