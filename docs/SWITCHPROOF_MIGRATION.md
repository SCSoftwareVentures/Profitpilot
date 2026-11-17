# ProfitPilot — SwitchProof Migration

**Capability:** fifth approved differentiator  
**Implementation stage:** synthetic, in-memory migration profiler and mapping preview  
**Status:** prototype only; not a live migration service

## Purpose

Help an Australian commercial-cleaning contractor assess whether legacy contract, site and invoice records can be mapped into ProfitPilot without silently losing source identity, hiding exceptions or overwriting existing information.

The first implementation stops before target writes. It demonstrates source profiling, explicit mapping, row-level validation, provenance and reconciliation using synthetic CSV fixtures.

## Implemented

- CSV structure profiling with a SHA-256 source checksum.
- Explicit source-header to canonical-target mapping.
- Versioned mapping fingerprint, stable across mapping key order.
- Strict target schema validation for text, exact decimal, ISO date, currency and boolean fields.
- Stable source record key requirement and duplicate-key hold.
- Source row number and per-row SHA-256 lineage.
- Every parsed row remains represented as a candidate or held exception.
- Unmapped source columns are surfaced.
- Parsed/previewed/candidate/held row reconciliation.
- Browser-compatible engine and interactive synthetic demo.
- Preview-only mode with zero target writes and a discard-based rollback statement.

## Safety and data boundaries

- The repository is public; use synthetic fixtures only.
- The prototype processes text locally in the browser demo. It does not upload or store source files, call an external service, access a customer system or write target records.
- A checksum establishes byte identity only. It does not establish source authenticity, lawful permission, correctness or ownership.
- Mapping candidates do not establish that two customer/site identities are the same.
- No automatic identity merge, destructive overwrite, approval, migration commit or rollback transaction is implemented.
- Do not use real customer, employee, payroll, invoice or confidential business data in this repository or browser demo.
- Real-data migration remains blocked until private object storage, access controls, malware scanning, retention/deletion, backup deletion verification, privacy/legal review and a documented permission basis are approved.

## Acceptance evidence

Automated tests cover stable source checksum, row-count reconciliation, exact decimal and strict date validation, duplicate source-key holds, explicit and unique field mapping, unmapped-column disclosure, mapping fingerprint stability/change detection, strict boolean parsing and preview-only non-persistence.

## Known limitations

- CSV only; no Excel, Google Sheets, accounting-provider or payroll-provider connectors.
- No binary file storage, quarantine or malware scanning.
- No semantic identity resolution, fuzzy matching or automated merge.
- No database persistence, signed approval, import commit, rollback transaction or background job.
- No real customer validation or evidence of migration time savings.

## Definition of done for this stage

A synthetic source can be profiled, mapped, validated and reconciled without target writes; exceptions remain visible; source lineage and mapping version are reproducible; automated tests pass; limitations are explicit.
