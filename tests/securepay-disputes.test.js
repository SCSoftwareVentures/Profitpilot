import test from 'node:test';
import assert from 'node:assert/strict';
import {openDispute,advanceDispute,responseTarget,verifyDispute} from '../src/securepay-disputes.js';
const I={tenant:'11111111-1111-4111-8111-111111111111',job:'22222222-2222-4222-8222-222222222222',
 case:'33333333-3333-4333-8333-333333333333',customer:'44444444-4444-4444-8444-444444444444',
 business:'55555555-5555-4555-8555-555555555555',reviewer:'66666666-6666-4666-8666-666666666666',
 other:'77777777-7777-4777-8777-777777777777'};
const C={id:I.customer,role:'customer'},B={id:I.business,role:'business'},
 R={id:I.reviewer,role:'reviewer'},R2={id:I.other,role:'reviewer'};
const cal={timeZone:'Australia/Melbourne',verified:true,verifiedThrough:'2027-12-31',holidays:['2026-12-25']};
let sequence=1;const id=()=>String(sequence++).padStart(8,'0')+'-8888-4888-8888-888888888888';
const opened=()=>openDispute({id:I.case,tenantId:I.tenant,jobId:I.job,customerId:I.customer,businessId:I.business,
 submittedAt:'2026-11-20T05:00:00Z',claimReference:'claim.001',clientRequestId:id()},C);
const step=(s,type,actor,details={},at='2026-11-21T02:00:00Z')=>advanceDispute(s,{type,actor,clientRequestId:id(),at,...details},cal);
const triaged=()=>step(opened(),'classify',R,{severity:'high',evidenceReference:'triage.001'});
const responded=()=>step(triaged(),'business_response',B,{evidenceReference:'business.001'});
const decision=()=>step(responded(),'decide',R,{remedy:'full_without_deduction',evidenceReference:'finding.001',
 customerEvidenceReference:'claim.001',businessEvidenceReference:'business.001'});
test('proposed SLAs respect business days and require a verified calendar',()=>{
 assert.equal(responseTarget({receivedAt:'2026-11-20T05:00:00Z',severity:'high',calendar:cal}).dueLocalDate,'2026-11-23');
 assert.equal(responseTarget({receivedAt:'2026-12-24T03:00:00Z',severity:'medium',calendar:cal}).dueLocalDate,'2026-12-30');
 assert.equal(responseTarget({receivedAt:'2026-11-20T05:00:00Z',severity:'low'}).dueLocalDate,null);
});
test('customer opens case; only independent reviewer may triage',()=>{
 const s=triaged();assert.equal(s.status,'awaiting_business');assert.equal(s.fundsMoved,false);assert.ok(verifyDispute(s));
 assert.throws(()=>step(opened(),'classify',C,{severity:'high',evidenceReference:'triage.001'}));
});
test('decision requires business response and both evidence references',()=>{
 assert.throws(()=>step(triaged(),'decide',R,{remedy:'no_adjustment',evidenceReference:'finding.001',
 customerEvidenceReference:'claim.001',businessEvidenceReference:'business.001'}));
 assert.throws(()=>step(responded(),'decide',R,{remedy:'no_adjustment',evidenceReference:'finding.001'}));
 assert.equal(decision().status,'decided');
});
test('rectification uses customer consent or independent impasse reviewer',()=>{
 const offer=step(responded(),'offer_rectification',B,{proposedDueDate:'2026-12-02',evidenceReference:'offer.001'});
 assert.equal(offer.status,'rectification_offered');
 assert.throws(()=>step(offer,'agree_rectification',B,{evidenceReference:'agree.001'}));
 const agreed=step(offer,'agree_rectification',C,{evidenceReference:'agree.001'});
 assert.equal(agreed.rectification.source,'agreed');
 const result=step(agreed,'rectification_result',C,{outcome:'satisfactory',evidenceReference:'result.001'});
 assert.equal(result.status,'under_review');
 const enforced=step(responded(),'set_rectification',R,{dueDate:'2026-12-04',impasseReference:'impasse.001',evidenceReference:'set.001'});
 assert.equal(enforced.rectification.source,'independent_review');
});
test('appeal reviewer is distinct and original decision is preserved',()=>{
 const a=step(decision(),'appeal',C,{evidenceReference:'appeal.001'});
 assert.throws(()=>step(a,'resolve_appeal',R,{outcome:'upheld',evidenceReference:'appealFinding.001'}));
 const b=step(a,'resolve_appeal',R2,{outcome:'upheld',evidenceReference:'appealFinding.001'});
 assert.equal(b.decision.reviewerId,I.reviewer);
 assert.equal(step(b,'close',R2,{evidenceReference:'close.001'}).status,'closed');
});
test('manual escalation never changes funds or transfers',()=>{
 let s=triaged();
 assert.throws(()=>step(s,'escalate',R,{reason:'response_sla_missed',evidenceReference:'late.001'}));
 s=step(s,'escalate',R,{reason:'response_sla_missed',evidenceReference:'late.001'},'2026-11-24T03:00:00Z');
 assert.equal(s.fundsMoved,false);assert.equal(s.status,'awaiting_business');
});
test('idempotency and tampering protections',()=>{
 const s=triaged(),e=s.events.at(-1);
 assert.equal(advanceDispute(s,{type:e.type,actor:R,at:e.at,clientRequestId:e.clientRequestId,...e.details},cal),s);
 assert.throws(()=>advanceDispute(s,{type:'business_response',actor:B,at:e.at,clientRequestId:e.clientRequestId,evidenceReference:'other.001'},cal));
 assert.equal(verifyDispute({...s,status:'closed'}),false);
 assert.equal(verifyDispute({...s,events:s.events.slice(1)}),false);
 assert.throws(()=>step(responded(),'decide',R,{remedy:'full_without_deduction',evidenceReference:'finding.001',
 customerEvidenceReference:'claim.001',businessEvidenceReference:'business.001',paymentAuthorised:true}));
});
test('partial deductions are proposals only, using whole cents',()=>{
 assert.throws(()=>step(responded(),'decide',R,{remedy:'partial_adjustment',adjustmentCents:1.5,evidenceReference:'finding.001',
 customerEvidenceReference:'claim.001',businessEvidenceReference:'business.001'}));
 const s=step(responded(),'decide',R,{remedy:'partial_adjustment',adjustmentCents:2500,evidenceReference:'finding.001',
 customerEvidenceReference:'claim.001',businessEvidenceReference:'business.001'});
 assert.equal(s.decision.adjustmentCents,2500);assert.equal(s.fundsMoved,false);
});

test('calendar-invalid UTC timestamps are rejected before SLA or case creation',()=>{
 const input={id:I.case,tenantId:I.tenant,jobId:I.job,customerId:I.customer,
  businessId:I.business,claimReference:'claim.001',clientRequestId:id()};
 for(const submittedAt of ['2026-02-30T05:00:00Z','2026-11-31T05:00:00Z',
  '2026-02-29T05:00:00Z','2026-11-20T24:00:00Z']){
  assert.throws(()=>openDispute({...input,submittedAt},C),/invalid opening actor or scope/);
  assert.throws(()=>responseTarget({receivedAt:submittedAt,severity:'high',calendar:cal}),/invalid receipt or severity/);
 }
});

test('historical exact retries remain idempotent after later events',()=>{
 const first=triaged(),later=step(first,'business_response',B,{evidenceReference:'business.001'},'2026-11-22T02:00:00Z');
 const e=first.events.at(-1);
 const replay={type:e.type,actor:R,at:e.at,clientRequestId:e.clientRequestId,...e.details};
 assert.equal(advanceDispute(later,replay,cal),later);
 assert.throws(()=>advanceDispute(later,{...replay,evidenceReference:'other.001'},cal),
  /conflicting idempotency key/);
 assert.throws(()=>advanceDispute(later,{...replay,clientRequestId:id()},cal),/backdated event/);
});

test('completed rectification cannot be misreported as overdue',()=>{
 const offer=step(responded(),'offer_rectification',B,
  {proposedDueDate:'2026-12-02',evidenceReference:'offer.001'});
 const agreed=step(offer,'agree_rectification',C,{evidenceReference:'agree.001'});
 const activeEscalation=step(agreed,'escalate',R,
  {reason:'rectification_overdue',evidenceReference:'late.001'},'2026-12-05T00:00:00Z');
 assert.equal(activeEscalation.status,'rectification');
 assert.equal(activeEscalation.fundsMoved,false);
 const completed=step(agreed,'rectification_result',C,
  {outcome:'satisfactory',evidenceReference:'result.001'});
 assert.throws(()=>step(completed,'escalate',R,
  {reason:'rectification_overdue',evidenceReference:'late.001'},'2026-12-05T00:00:00Z'),
  /rectification not overdue/);
});
