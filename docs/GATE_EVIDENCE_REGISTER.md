# G0–G5 buyer-validation evidence register (controlled template)

**Status:** No real customer evidence is asserted by this template. All gates remain **BLOCKED / NOT VERIFIED** until dated, permissioned evidence is recorded and independently reviewed. This document does not authorise software development, deployment, outreach, or collection of personal data.

## Evidence record schema

Each evidence record must contain:
- `evidence_id`: immutable unique identifier; `gate`: G0–G5; `criterion_id`: criterion below.
- `source_type`: interview / export / competitor teardown / concierge trial / paid commitment / usability session / signed approval.
- `source_date`, `collected_at`, `reviewed_at`, `reviewer`, `method_version`.
- `business_alias` and `independence_group` (no real personal names in public repository).
- `authority_basis`, `permitted_purpose`, `retention_until`, `consent_or_contract_reference`.
- `evidence_locator`: access-controlled pointer only, **never customer exports, credentials, raw payroll or identifiable interviews in this public repo**.
- `eligible` (true/false), `exclusion_reason`, `observed_numerator`, `observed_denominator`, `outcome`, `exceptions`.
- `review_decision`: PASS / FAIL / BLOCKED; `decision_reason`.

## Gate-by-gate acceptance ledger

| Criterion ID | Required evidence | Threshold | Initial state |
|---|---|---|---|
| G0-EXPORT | Complete authorised export sets from independent businesses | >=5 sets, >=3 unrelated businesses | BLOCKED |
| G0-PAYROLL | Per-set attributable payroll pool | >=80% in >=80% of eligible unique sets | BLOCKED |
| G0-INVOICE | Per-set invoice value matched at medium/high confidence | >=80% in >=80% of eligible unique sets | BLOCKED |
| G0-TIME | One-site baseline elapsed customer and analyst effort | <=120 customer minutes AND <=180 analyst minutes in >=80% of eligible unique sets | BLOCKED |
| G0-RECON | Row counts, monetary totals, tax basis and rounding reconciled | All evaluated sets must document reconciliation; exceptions disclosed | BLOCKED |
| G0-COMP | Hands-on competitor and tool-stack teardowns | >=5 products and >=2 real customer stacks, same scenarios | BLOCKED |
| G0-GAP | Independently observed recurring unmet gap | >=2 independent customers, >=1 willingness-to-pay buyer | BLOCKED |
| G1-INTERVIEW | Interview diversity and independent pain | >=20 interviews, >=3 channels, founder network <=40%, >=12 spontaneous pain, >=8 quantified examples | BLOCKED |
| G2-TRIAL | No-obligation concierge trials | >=3 unrelated businesses, >=2 decision-useful confirmations | BLOCKED |
| G3-DEMAND | Qualified buyers and paid evidence | >=10 buying conversations, >=3 paid engagements or signed commitments | BLOCKED |
| G4-USABILITY | Moderated sessions | >=8 sessions, >=6 unaided completions, median first-insight <=30 minutes | BLOCKED |
| G5-GO | Signed authorisation after all prerequisite gates | Signed GO, named technical owner, legal/privacy plan, capacity, budget | BLOCKED |

## Evaluation rules (fail closed)

1. **No fabricated denominator:** missing, partial, duplicate, or unauthorised evidence cannot be counted as a pass. Record excluded sets and reasons explicitly.
2. **No synthetic promotion:** synthetic data may test workflows but contributes **zero** to customer, payment, interview and real-export thresholds.
3. **No selective sampling:** report all unique complete sets received in the evaluation period, not just favourable sets; use ceiling(0.8 × eligible unique complete sets) for the 80%-of-sets tests. Report eligibility and exclusions before computing.
4. **Independence:** related companies, subsidiaries and duplicate respondent businesses must be reviewed for independence before counting.
5. **Monetary audit:** store currency, tax-inclusive/exclusive basis, refunds/credits, rounding rules, reconciliation differences and unresolved exceptions in protected evidence records.
6. **Privacy:** no source exports, customer names, contact details, payroll, signed contracts or tokens in GitHub. Use aliases and protected external evidence locators; access requires explicit authorisation.
7. **Reviewer separation:** evidence collector and gate approver should be different people where feasible. Log conflicts and any overrides; no silent waivers.
8. **Decision:** G5 cannot pass if any G0–G4 prerequisite is FAIL or BLOCKED. Only an explicit signed GO can authorise full software build. Do not infer approval from successful prototype CI.

## Next permitted work (without external outreach)

- Prepare synthetic scenario fixtures and repeatable reconciliation test cases.
- Review prototype usability and evidence capture flow with fictional data.
- Draft interview, teardown and concierge scripts **for later approval**, without contacting businesses.
- Run existing tests and fix prototype defects on draft branches.

## Current release / sale disclosure

ProfitPilot currently contains prototype and planning work. Customer feasibility, paid demand, lawful real-data access, full product readiness and sale valuation are **unverified**. This register is a blank control mechanism, not validation evidence.
