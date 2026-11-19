# ProfitPilot — Initial MVP Product Requirements

**Version:** 1.0  
**Status:** proposed product requirements; not implementation or build authorisation  
**Initial segment:** Australian independent commercial cleaning contractors with recurring, multi-site B2B contracts  
**Primary analysis grain:** contract × site × service period × calculation version

## 1. Product objective

Give a business owner or operations/finance lead a trustworthy view of whether contract delivery economics are supported by available source evidence, where the records do not reconcile, and what human decision is required next.

The MVP is not intended to replace payroll, accounting, invoicing, tax or bank systems. Those systems remain authoritative for their respective source records. ProfitPilot links evidence, reconciles defined data and produces a management view with explicit coverage and limitations.

## 2. Users and jobs to be done

| User | Primary job | MVP authority |
|---|---|---|
| Business owner | Understand contract/site economics and approve material decisions | Workspace owner; may approve only under configured role policy |
| Operations manager | Resolve site, service-period and scope exceptions | Review operational context and propose corrections |
| Finance/bookkeeping analyst | Import and reconcile records, review match evidence and prepare reports | Import, map and analyse within granted scope |
| Financial reviewer | Confirm allocations, invoice matches and financial review decisions | Explicit reviewer permission; no self-approval where separation is configured |
| Read-only stakeholder | View permitted reports and evidence summaries | Read-only access; no mutation |

Users may hold multiple roles only where the tenant permission model and separation-of-duty rules explicitly allow it. The application must never infer approval authority from job title or client-side UI state.

## 3. Core user outcomes

1. Establish a versioned contract/site/service-period baseline.
2. Register and reconcile an authorised source bundle.
3. Preserve source rows and mapping history.
4. Reconcile the authoritative payroll pool across direct-coded, approved allocated, non-site, unallocated and excluded buckets.
5. Link eligible invoice value to contract/site/service period using evidence and human confirmation.
6. Preserve observed/requested variations separately from approved value.
7. Produce an incomplete-aware management contribution bridge.
8. Show material exceptions, quantified only where evidence supports a number.
9. Trace every material output back to source records, policy versions and reviewer decisions.
10. Export a report that preserves limitations and provenance.

## 4. In-scope functional requirements

### Workspace and setup

| ID | Requirement | Acceptance condition |
|---|---|---|
| MVP-001 | Create a tenant workspace and business profile | Stable tenant/business IDs; no cross-tenant lookup possible |
| MVP-002 | Capture business industry and operating model | Initial target template can be selected; unsupported industries are labelled unsupported rather than forced into cleaning workflows |
| MVP-003 | Invite users and assign roles | Server enforces role and tenant membership for every action |
| MVP-004 | Configure currency, timezone and reporting conventions | No silent currency or timezone default in financial calculations |
| MVP-005 | Maintain searchable permanent records | Jobs/commitments/decisions introduced in later phases receive stable IDs; first release provides search over supported contract, import, exception and calculation records |

### Contracts, sites and service periods

| ID | Requirement | Acceptance condition |
|---|---|---|
| MVP-010 | Create customer, contract and site records | Each record has immutable ID, tenant scope and audit history |
| MVP-011 | Version commercial baseline | New approved scope/price/billing terms create a new version; prior version remains readable |
| MVP-012 | Define service period | Period boundary, timezone and status are explicit |
| MVP-013 | Capture inclusions, exclusions and billing basis | Reports show the exact baseline version and evidence reference |
| MVP-014 | Prevent ambiguous scope from being represented as confirmed | Missing or disputed fields remain incomplete/pending |

### Imports and source lineage

| ID | Requirement | Acceptance condition |
|---|---|---|
| MVP-020 | Register import metadata and permission reference | Status is registered until binary bytes are securely stored and verified |
| MVP-021 | Securely receive source files | Only after private storage, quarantine, file validation and malware scanning exist |
| MVP-022 | Preserve source manifest and row identity | Each normalised fact links to tenant, file checksum, batch, row, source system and parser/mapping version |
| MVP-023 | Reconcile row and monetary controls | Row counts and declared monetary totals reconcile; otherwise batch remains held/unreconciled |
| MVP-024 | Support idempotent replay | Same source checksum and scope does not duplicate facts or monetary value |
| MVP-025 | Preserve null, zero and unknown separately | Missing or malformed amount is never coerced to zero |
| MVP-026 | Review mapping candidates | Ambiguous site/customer/contract identity remains held until approved |
| MVP-027 | Preserve reversals and restatements | Changed mapping creates a new version and audit event; prior output remains available |

### Payroll pool and allocation

| ID | Requirement | Acceptance condition |
|---|---|---|
| MVP-030 | Preserve authoritative payroll pool total | Source total and period are recorded; ProfitPilot does not recalculate statutory payroll obligations |
| MVP-031 | Classify every eligible source row | Mutually exclusive buckets: DIRECT_CODED, APPROVED_ALLOCATED, NON_SITE, UNALLOCATED, EXCLUDED |
| MVP-032 | Enforce source-row allocation cap | Confirmed allocations never exceed the row's eligible exact amount |
| MVP-033 | Enforce pool reconciliation | Sum of mutually exclusive buckets equals authoritative source pool under approved source policy |
| MVP-034 | Require evidence for approved allocation | Method, version, source references, reviewer, reason and time are recorded |
| MVP-035 | Keep candidates out of confirmed totals | Unapproved suggestions never affect approved site allocation |
| MVP-036 | Preserve negative values and corrections | Credits/reversals retain sign under an approved policy; no silent clamp to zero |
| MVP-037 | Restate without overwriting | Recalculation creates a new immutable run linked to the old run and reason |

### Invoice evidence and coverage

| ID | Requirement | Acceptance condition |
|---|---|---|
| MVP-040 | Import eligible customer invoice lines | Raw and normalised values remain traceable |
| MVP-041 | Generate match candidates from multiple evidence dimensions | Customer, contract, site, service period, amount, currency, tax basis, source IDs and conflicts are visible |
| MVP-042 | Separate confidence from decision | Confidence describes evidence quality; only a permitted human reviewer can confirm |
| MVP-043 | Detect duplicates and conflicting candidates | Candidate conflict is held; duplicate source replay cannot double count |
| MVP-044 | Define eligible denominator | Versioned rules cover credits, cancellations, duplicates and out-of-scope lines |
| MVP-045 | Calculate match coverage | Numerator includes only eligible value with medium/high evidence and human-confirmed contract/site/service-period mapping |

### Variations and contribution

| ID | Requirement | Acceptance condition |
|---|---|---|
| MVP-050 | Record requested/observed variation | Candidate/observed status is not approved or billable |
| MVP-051 | Record authorised approval/rejection | Actor, authority, time, scope, price, evidence and effective period retained |
| MVP-052 | Separate delivered, invoiced and accepted values | No state is inferred from another state |
| MVP-053 | Compute management contribution only on comparable, complete inputs | Currency, tax basis, period and cost/revenue policy must align |
| MVP-054 | Suppress definitive contribution/margin on material missing data | Result is unavailable/incomplete with missing categories and coverage disclosed |
| MVP-055 | Disclose non-site, unallocated, excluded and estimated values | Never silently spread residuals over sites |
| MVP-056 | Label management contribution limitations | Never label as audited, statutory, net or tax profit |

### Exceptions, reporting and audit

| ID | Requirement | Acceptance condition |
|---|---|---|
| MVP-060 | Maintain a traceable exception register | Every exception has source, owner, due date, status and closure evidence |
| MVP-061 | Quantify only supportable discrepancies | Unsupported amount is shown as unknown/range, not fabricated |
| MVP-062 | Show calculation coverage and version | Every report identifies period, sources, policies, engine version and incomplete items |
| MVP-063 | Export traceable report | Export is tenant-scoped, audited and safe against spreadsheet formula injection |
| MVP-064 | Append audit events for material actions | Actor, role, action, timestamp, reason and object/source references recorded |
| MVP-065 | Support authorised data export and deletion | Verified deletion, legal holds and backup expiry are handled under approved policy |

## 5. Non-functional requirements

- Tenant isolation: deny by default at API, data-access, database and storage layers.
- Authentication: managed OIDC/OAuth with Authorization Code + PKCE; MFA for privileged users; secure recovery and revocation.
- Authorization: server-side object and action checks; separation of duties for approvals and exports.
- Financial integrity: no JavaScript Number in authoritative money path; exact decimal strings and database NUMERIC with approved scale.
- Provenance: source, parser/mapping version, reviewer and calculation policy remain linkable.
- Determinism: identical source facts and policies reproduce identical output.
- Resilience: safe retry, idempotency and visible sync state; offline actions cannot silently conflict.
- Privacy: data minimisation, purpose limitation, retention, export and deletion.
- Accessibility: target WCAG 2.2 AA; status never communicated by colour alone.
- Mobile usability: critical workflows work on supported iPhone browsers and screen sizes.
- Observability: operational logs exclude secrets and unnecessary sensitive payloads; actionable alerts and audit trails exist.
- Recovery: defined and tested backup/restore, RPO/RTO and incident response before launch.

These are acceptance requirements, not claims of current implementation.

## 6. Explicit non-goals for MVP

- Authoritative payroll processing, award interpretation or statutory entitlements.
- Full accounting/general ledger replacement, tax returns or audited financial statements.
- Automatic invoice approval, payment or dispute adjudication.
- Payment custody, escrow, stored value or internal payout release.
- Marketplace search, provider ratings, public reviews or broad CRM.
- AI-authorised calculation, financial match confirmation, variation approval or money movement.
- Unvalidated support for every trade or enterprise process.

## 7. Primary acceptance journeys

1. New owner creates a cleaning-business workspace, selects the supported operating template and invites a reviewer.
2. Analyst registers an authorised period bundle; missing binary storage, authority or manifest data prevents intake from being represented as completed upload.
3. Analyst reviews site/contract mappings; unknowns remain held.
4. Reviewer confirms row-level payroll classification and the pool reconciles exactly.
5. Analyst reviews invoice candidates; only authorised human confirmations enter the coverage numerator.
6. Owner reviews approved and unapproved variations separately.
7. Owner opens a contract/site/service-period report; missing inputs suppress definitive margin and are visible.
8. Owner exports a traceable report and can retrieve the calculation version and source lineage.

## 8. Definition of done

A requirement is complete only when:
- acceptance criteria are mapped to executable tests;
- test evidence is attached to an exact commit and environment;
- expected financial results are independently reviewed;
- authorization, tenant, privacy and audit controls are verified;
- accessibility, mobile, error and recovery states are tested;
- documentation and support processes are updated;
- known limitations are visible to users.

This document does not authorise implementation. G0–G4 and competitive preconditions must pass; G5 signed GO is required before production feature coding.
