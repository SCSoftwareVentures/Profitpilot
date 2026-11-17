# ProfitPilot — Buyer Trust Pack Index

**Revision:** 17 November 2026  
**Audience:** Prospective acquirers and their technical, security and privacy advisers  
**Purpose:** A concise route into the current evidence set. This pack is deliberately explicit about prototype limitations.

## Five-minute review path

1. [Security, Trust & Privacy Overview](BUYER_SECURITY_PRIVACY_OVERVIEW.md) — executive summary, implemented controls, architecture, verification and limitations.
2. [Security Architecture Diagram](SECURITY_ARCHITECTURE_DIAGRAM.md) — current trust boundaries and production components not yet established.
3. [Security & Privacy Control Evidence Matrix](SECURITY_PRIVACY_EVIDENCE_MATRIX.md) — each control mapped to code evidence, tests and remaining work.
4. [Preliminary Privacy Data Inventory](PRIVACY_DATA_INVENTORY.md) — schema-derived data categories and lifecycle gaps.
5. [Audit Evidence Format](AUDIT_EVIDENCE_FORMAT.md) — structure and verification model for audit events; sample is explicitly synthetic.

## Supporting engineering references

- [Trust, Security & Privacy Standard](TRUST_SECURITY_PRIVACY_STANDARD.md)
- [Privacy Engineering Baseline](PRIVACY_ENGINEERING_BASELINE.md)
- [Threat Model](THREAT_MODEL.md)
- [Architecture](ARCHITECTURE.md)
- [Verification Matrix](VERIFICATION_MATRIX.md)
- [Implementation Audit](IMPLEMENTATION_AUDIT.md)
- [Project Status](PROJECT_STATUS.md)
- [Risk Register](RISK_REGISTER.md)

## CI evidence

- [Run #1046 — passed](https://github.com/luxhustle01-ux/Profitpilot/actions/runs/44002838128): verifies the earlier privacy subject-isolation milestone, including migrations/RLS, authenticated API integration, Node.js checks, container build and health check.
- The subsequent fail-closed privacy fulfilment change and buyer-pack documents require a fresh passing CI run. Check the branch's latest workflow result before treating those later changes as verified.

## Acquirer diligence checklist

- [ ] Review repository history and confirm the exact branch/commit being acquired.
- [ ] Repeat the full CI suite from a clean checkout.
- [ ] Review all migrations, RLS policies, definer functions and grants with an independent PostgreSQL/security specialist.
- [ ] Verify ownership and transferability of source code, brand, domains, design assets and third-party dependencies.
- [ ] Obtain an independent penetration test and remediation retest.
- [ ] Complete an environment-specific privacy impact assessment and qualified legal review.
- [ ] Reconcile the data inventory against actual infrastructure, backups, logs and processors.
- [ ] Implement and test secure uploads, data exports, corrections, restrictions, deletion, backup expiry and restoration.
- [ ] Configure production identity, MFA/passkeys, secret/key custody, monitoring, incident response and recovery.
- [ ] Confirm the buyer accepts all disclosed limitations and the no-production-readiness position.

## Important acquisition statement

This pack demonstrates documented engineering intent, implemented prototype controls and bounded automated test evidence. It does not establish a production deployment, production security, legal compliance, independent assurance, customer adoption or revenue. Do not remove this qualification from any buyer-facing copy.
