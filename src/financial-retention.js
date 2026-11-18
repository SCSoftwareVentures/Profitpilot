// Pure candidate-only planner. Inputs are externally supplied assertions, not verified authorisations.
// No database access, deletion, approval, or release authority. Do not use this as an execution gate.
export function evaluateRetentionCandidate(input) {
  const deny = reason => Object.freeze({status:'blocked',reason,authorizesDisposal:false});
  const exact = (x,keys) => x !== null && typeof x === 'object' && !Array.isArray(x) && Object.keys(x).length===keys.length && keys.every(k=>Object.hasOwn(x,k));
  const digest = v => typeof v==='string' && /^[a-f0-9]{64}$/.test(v) && v!=='0'.repeat(64);
  const date = v => typeof v==='string' && /^\d{4}-\d{2}-\d{2}$/.test(v) && Number.isFinite(Date.parse(v+'T00:00:00Z')) && new Date(v+'T00:00:00Z').toISOString().slice(0,10)===v;
  if (!exact(input,['asOf','recordClass','recordDigest','policy','holds','dependencies','backup'])) return deny('invalid-input');
  const {asOf,recordClass,recordDigest,policy,holds,dependencies,backup}=input;
  if (!date(asOf) || !digest(recordDigest) || !['confirmed_payroll','confirmed_invoice','financial_audit_evidence'].includes(recordClass)) return deny('invalid-record');
  if (!exact(policy,['recordClass','recordDigest','evidenceDigest','reviewedOn','reviewExpiresOn','requirements']) || policy.recordClass!==recordClass || policy.recordDigest!==recordDigest || !digest(policy.evidenceDigest) || !date(policy.reviewedOn) || !date(policy.reviewExpiresOn) || policy.reviewedOn>asOf || policy.reviewExpiresOn<=asOf || !Array.isArray(policy.requirements) || policy.requirements.length===0 || policy.requirements.length>32) return deny('policy-unverified-or-stale');
  const unique = new Set();
  let latest='0000-01-01';
  for (const rule of policy.requirements) {
    if (!exact(rule,['authorityDigest','retainThrough']) || !digest(rule.authorityDigest) || !date(rule.retainThrough) || unique.has(rule.authorityDigest)) return deny('invalid-retention-requirement');
    unique.add(rule.authorityDigest);
    if(rule.retainThrough>latest)latest=rule.retainThrough;
  }
  if (asOf<=latest) return deny('retention-period-active');
  if (!exact(holds,['recordDigest','checkedOn','state','evidenceDigest']) || holds.recordDigest!==recordDigest || holds.checkedOn!==asOf || holds.state!=='clear' || !digest(holds.evidenceDigest)) return deny('legal-hold-unresolved');
  if (!exact(dependencies,['recordDigest','checkedOn','state','evidenceDigest']) || dependencies.recordDigest!==recordDigest || dependencies.checkedOn!==asOf || dependencies.state!=='clear' || !digest(dependencies.evidenceDigest)) return deny('dependency-unresolved');
  if (!exact(backup,['recordDigest','checkedOn','state','evidenceDigest']) || backup.recordDigest!==recordDigest || backup.checkedOn!==asOf || backup.state!=='verified-disposition-plan' || !digest(backup.evidenceDigest)) return deny('backup-unresolved');
  return Object.freeze({status:'eligible-for-independent-review',retainThrough:latest,authorizesDisposal:false});
}
