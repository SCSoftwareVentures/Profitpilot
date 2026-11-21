// Synthetic-only preflight: operator reports are NOT verified party submissions.
// This function must never issue an approve, release, settle or transfer instruction.
const safeCount=n=>Number.isSafeInteger(n)&&n>=0;
export function assessSecurepayDecisionPreflight(caseRow,counts){
 if(!caseRow||caseRow.synthetic!==true||caseRow.funds_moved!==false||
  caseRow.status!=="evidence_pending"||typeof caseRow.id!=="string"||
  typeof caseRow.opened_by_requester!=="boolean"||!counts)
  throw new TypeError("Invalid synthetic SecurePay preflight case");
 const keys=["total","claim_reports","business_reports","review_notes","externally_verified"];
 if(keys.some(k=>!safeCount(counts[k]))||
  counts.claim_reports+counts.business_reports+counts.review_notes>counts.total||
  counts.externally_verified!==0)
  throw new TypeError("Invalid or unexpectedly verified SecurePay evidence counts");
 const claim=counts.claim_reports>0,business=counts.business_reports>0,note=counts.review_notes>0;
 const blockingGates=[
  ...(!claim?["matching_claim_report_missing"]:[]),
  ...(!business?["business_response_report_missing"]:[]),
  ...(!note?["operator_review_note_missing"]:[]),
  ...(caseRow.opened_by_requester?["requester_must_not_self_review"]:[]),
  "customer_identity_unverified",
  "business_identity_unverified",
  "evidence_provenance_unverified",
  "independent_reviewer_unverified",
  "authoritative_decision_events_not_connected",
  "provider_and_legal_clearance_unverified"
 ];
 return {
  caseId:caseRow.id,caseStatus:caseRow.status,synthetic:true,
  decisionReadiness:"blocked",decisionAuthority:false,paymentAuthority:false,fundsMoved:false,
  partyIdentityVerified:false,evidenceOriginVerified:false,reviewerIndependenceVerified:false,
  requesterOpenedCase:caseRow.opened_by_requester,
  evidence:{totalOperatorReports:counts.total,matchingClaimReported:claim,
   businessResponseReported:business,operatorReviewNoteReported:note,externallyVerifiedCount:0},
  blockingGates
 };
}
