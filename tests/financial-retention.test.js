import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateRetentionCandidate } from '../src/financial-retention.js';
function fixture() {
 const d=(c)=>c.repeat(64); const recordDigest=d('a');
 return {asOf:'2035-01-02',recordClass:'confirmed_payroll',recordDigest,policy:{recordClass:'confirmed_payroll',recordDigest,evidenceDigest:d('b'),reviewedOn:'2035-01-01',reviewExpiresOn:'2035-02-01',requirements:[{authorityDigest:d('c'),retainThrough:'2034-12-31'},{authorityDigest:d('d'),retainThrough:'2035-01-01'}]},holds:{recordDigest,checkedOn:'2035-01-02',state:'clear',evidenceDigest:d('e')},dependencies:{recordDigest,checkedOn:'2035-01-02',state:'clear',evidenceDigest:d('f')},backup:{recordDigest,checkedOn:'2035-01-02',state:'verified-disposition-plan',evidenceDigest:d('1')}};
}
const cases = [
  ["all barriers clear", x=>{}, "eligible-for-independent-review"],
  ["retention deadline inclusive", x=>{x.policy.requirements[1].retainThrough=x.asOf}, "retention-period-active"],
  ["longer obligation controls", x=>{x.policy.requirements[0].retainThrough='2036-01-01'}, "retention-period-active"],
  ["active legal hold", x=>{x.holds.state='active'}, "legal-hold-unresolved"],
  ["unknown hold", x=>{delete x.holds.state}, "legal-hold-unresolved"],
  ["stale hold evidence", x=>{x.holds.checkedOn='2035-01-01'}, "legal-hold-unresolved"],
  ["record-bound evidence", x=>{x.holds.recordDigest='9'.repeat(64)}, "legal-hold-unresolved"],
  ["referenced evidence", x=>{x.dependencies.state='referenced'}, "dependency-unresolved"],
  ["backup unknown", x=>{x.backup.state='unknown'}, "backup-unresolved"],
  ["expired legal review", x=>{x.policy.reviewExpiresOn=x.asOf}, "policy-unverified-or-stale"],
  ["wrong policy class", x=>{x.policy.recordClass='confirmed_invoice'}, "policy-unverified-or-stale"],
  ["no retention rules", x=>{x.policy.requirements=[]}, "policy-unverified-or-stale"],
  ["duplicate authority", x=>{x.policy.requirements[1].authorityDigest=x.policy.requirements[0].authorityDigest}, "invalid-retention-requirement"],
  ["invalid date", x=>{x.policy.requirements[0].retainThrough='2034-02-30'}, "invalid-retention-requirement"],
  ["empty evidence digest", x=>{x.policy.evidenceDigest='0'.repeat(64)}, "policy-unverified-or-stale"],
  ["forged authorization field", x=>{x.authorizesDisposal=true}, "invalid-input"],
  ["missing input", x=>{delete x.backup}, "invalid-input"],
  ["unsupported record class", x=>{x.recordClass='unclassified'}, "invalid-record"],
  ["policy from future", x=>{x.policy.reviewedOn='2035-01-03'}, "policy-unverified-or-stale"],
  ["cross-record policy", x=>{x.policy.recordDigest='9'.repeat(64)}, "policy-unverified-or-stale"],
  ["cross-record backup plan", x=>{x.backup.recordDigest='9'.repeat(64)}, "backup-unresolved"]
];
for(const [name, mutate, expected] of cases) test(name, () => { const input=fixture(); mutate(input); const outcome=evaluateRetentionCandidate(input); assert.equal(outcome.reason??outcome.status,expected); assert.equal(outcome.authorizesDisposal,false); });
