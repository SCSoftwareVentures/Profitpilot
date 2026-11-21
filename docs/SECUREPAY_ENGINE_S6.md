# SecurePay SP-S6 — self-supplied Ed25519 signed party-to-job **claims**

## What has been cryptographically verified
The backend validates an Ed25519 signature over a canonical, domain-separated statement containing the *authenticated tenant's* case ID, the existing evidence ID and provenance receipt ID, the case's **opaque** job reference, the existing evidence type/reference and provenance metadata digest, the signer's **claimed** customer/tradesperson role, a client-**claimed** content hash, and a nonce. The same statement can be independently recomputed from append-only database records and verified again using the retained public key and signature. A mismatch, malformed key/signature, foreign case/evidence or altered content claim is rejected. Database composite foreign keys and forced tenant RLS constrain record associations. No raw file content is accepted.

## What is NOT verified
The submitted public key is **self-supplied**. Valid cryptography proves the signer held its private key; it does **not** prove the signer is the job's real customer/tradesperson, that a trusted identity provider issued or bound the key, that the party had authority for the job, that a source document exists or matches the client-supplied hash, or that a custodian retained the bytes. All issuer trust, human identity, job authority, content verification, decision authority, and payment authority are explicitly false, both in the API and by database CHECK constraints. This is a synthetic prototype, never a binding e-signature or lawful transaction authorisation.

## Routes
- `POST /v1/tenants/:tenantId/prototype/securepay-cases/:caseId/evidence/:evidenceId/signed-party-claims`
- `GET` on the same collection (100 per page)
- `GET .../signed-party-claims/:claimId/verify-signature` rechecks the stored signature against current immutable source metadata. This returns `cryptographicSignatureValid` only, **not** identity or job authority.

POST accepts **exactly** seven fields:
`clientRequestId` UUID, `provenanceReceiptId` UUID,
`claimedPartyRole` (`customer` or `tradesperson`),
`keySpki` (canonical base64url DER Ed25519 public key),
`nonce` UUID, `claimedContentSha256` (lowercase 64-hex digest of *unverified* bytes),
and `signature` (canonical base64url 64-byte Ed25519 signature).
The server supplies case/evidence/job metadata from trusted tenant RLS-scoped queries, not the request. Only `reported_customer` provenance of `claim_reported` evidence may claim customer, and only `reported_business` provenance of `business_response_reported` evidence may claim tradesperson. This is a **reported** alignment, not corroboration. Each request is idempotently recorded with the authenticated operator, or rejected on conflicting replay. No private keys, raw files, personal data or payment instructions are accepted.

**Future:** A genuinely independent issuer-backed identity and job-authority attestation service, verified consent/role resolution and revocation, protected source bytes with malware scanning/content hash, tamper-evident external anchoring, independent reviewer appointment, privacy and Australian legal/payment-provider clearance. Never release funds on a self-supplied key's signature.
