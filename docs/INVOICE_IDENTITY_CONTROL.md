# Invoice identity and evidence control — proposed validation specification

Status: synthetic preview implemented; production invoice identity enforcement remains proposed. No G5 build approval implied.

## Observed gaps
The original-file endpoint checks SHA-256 and seals rows; the CSV parser rejects repeated trimmed invoice IDs within one file. The legacy JSON endpoint accepts row objects; the structural validator now holds repeated references within a validation batch. Batch locking does not serialize separate batches. File identity is not invoice identity. Existing CSV schema contains invoice_id, site, date, amount but no stable issuer/account identity or currency; invoice numbers alone cannot safely identify supplier invoices across issuers.

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
Push-triggered CI #2963 passed at cba35f2, including the preceding source-receipt and synthetic-preview work. New classifier changes require their own verification. Obtain authorised representative exports under G0 and verify issuer/reference semantics before schema enforcement. Production build remains gated by G0–G5.

## Follow-up database audit
Migration 005 already enforces one confirmed match per tenant/invoice line and one confirmed allocation run per payroll pool using partial unique indexes. The latest calculation guard is defense in depth, not a replacement for these indexes. The base invoices table also has UNIQUE(tenant_id,direction,invoice_number), which blocks duplicate numbers but conflates distinct supplier issuers. Do not drop that constraint until an issuer-aware replacement and migration conflict inventory are validated. Raw import rows still permit repeated references across separate files; candidate evidence must not be confused with canonical invoices. CI configuration runs on pushes, whereas the available commit workflow lookup filters to pull requests; empty results are not evidence that CI did not run.

## Synthetic preview conflict grouping
The preview now performs two passes over a bounded synthetic input. All members of an exact issuer/reference conflict or potential alias group are held, including the first observed row. A distinct issuer or direction is a separate namespace; issuer keys remain case-sensitive pending source-owner rules. Alias detection (case and leading-zero numeric variants) is a review signal, not canonicalisation. The preview never persists rows, authenticates issuers or permits financial inclusion; it does not detect cross-request duplicates. Regression coverage includes reversed order, malformed rows, source immutability and namespace isolation.

## Persistent review reservations (migration 012)
Reviewers may reserve a stable lower-case issuer namespace against a structurally valid invoice raw row. The database enforces same-tenant source/reviewer references, invoice direction and exact trimmed source reference, actual receipt status, reviewer role, immutable runtime record and uniqueness across batches for exact references and conservative ASCII-case/numeric-leading-zero aliases. Exact reviewer replay is idempotent; other collisions fail atomically. A read endpoint lists potential other-batch conflicts by reference and direction even before issuer assignment. The reservation is reviewer-attested rather than issuer-authenticated; its creation does not generate a canonical financial invoice, confirm a match or allow financial inclusion. Distinct issuers remain separate in the reservation registry only. Existing invoice uniqueness remains unchanged and legacy invoices are not retroactively certified. Corrections and source-owner semantics require further design/validation. New CI evidence pending.
