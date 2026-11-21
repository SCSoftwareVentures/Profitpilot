import {createHash} from "node:crypto";
const uuid=x=>typeof x==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(x);
const ref=x=>typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(x);
export const MAX_REVIEW_REPORTS=500;
// Only an internal synthetic operator report check. Never a decision or payment authorisation.
export function checkOperatorReviewer(caseRow,rows,reviewerId){
 if(!caseRow||!uuid(caseRow.id)||!uuid(caseRow.tenant_id)||!uuid(caseRow.opened_by)||
 !ref(caseRow.claim_reference)||caseRow.synthetic!==true||caseRow.funds_moved!==false||
 caseRow.status!=="evidence_pending"||!uuid(reviewerId)||!Array.isArray(rows)||rows.length>MAX_REVIEW_REPORTS)
  throw new TypeError("Invalid synthetic operator review scope");
 const ids=new Set();
 const data=rows.map(r=>{
  const stamp=r?.recorded_at instanceof Date?r.recorded_at.toISOString():r?.recorded_at;
  if(!r||!uuid(r.id)||!uuid(r.recorded_by)||!uuid(r.client_request_id)||!ref(r.evidence_reference)||
  !["claim_reported","business_response_reported","operator_review_note","rectification_reported","appeal_reported"].includes(r.evidence_type)||
  r.externally_verified!==false||typeof stamp!=="string"||!Number.isFinite(Date.parse(stamp))||ids.has(r.id))
   throw new TypeError("Invalid operator evidence snapshot");
  ids.add(r.id);return [r.id,r.client_request_id,r.recorded_by,r.evidence_type,r.evidence_reference,stamp];
 });
 const gates=[
 ...(caseRow.opened_by===reviewerId?["reviewer_opened_case"]:[]),
 ...(rows.some(r=>r.recorded_by===reviewerId)?["reviewer_recorded_evidence"]:[]),
 ...(!rows.some(r=>r.evidence_type==="claim_reported"&&r.evidence_reference===caseRow.claim_reference)?["matching_claim_report_missing"]:[]),
 ...(!rows.some(r=>r.evidence_type==="business_response_reported")?["business_response_report_missing"]:[]),
 ...(!rows.some(r=>r.evidence_type==="operator_review_note")?["operator_review_note_missing"]:[])
 ];
 return {eligibleForNonbindingOperatorReview:gates.length===0,blockingGates:gates,
  evidenceCount:rows.length,evidenceSnapshotSha256:createHash("sha256").update(JSON.stringify({
   caseId:caseRow.id,tenantId:caseRow.tenant_id,claimReference:caseRow.claim_reference,rows:data
  })).digest("hex"),decisionAuthority:false,paymentAuthority:false,partyIdentityVerified:false};
}
