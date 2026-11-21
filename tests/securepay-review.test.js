import test from "node:test";
import assert from "node:assert/strict";
import {checkOperatorReviewer,MAX_REVIEW_REPORTS} from "../src/securepay-review.js";
const owner="11111111-1111-4111-8111-111111111111",reviewer="22222222-2222-4222-8222-222222222222";
const c={id:"33333333-3333-4333-8333-333333333333",tenant_id:"44444444-4444-4444-8444-444444444444",opened_by:owner,claim_reference:"claim.s3",synthetic:true,funds_moved:false,status:"evidence_pending"};
const e=(n,type,r,actor=owner)=>({id:String(n).padStart(8,"0")+"-5555-4555-8555-555555555555",client_request_id:String(n).padStart(8,"0")+"-6666-4666-8666-666666666666",recorded_by:actor,evidence_type:type,evidence_reference:r,externally_verified:false,recorded_at:new Date("2026-11-21T00:00:00Z")});
const rows=[e(1,"claim_reported","claim.s3"),e(2,"business_response_reported","business.s3"),e(3,"operator_review_note","note.s3")];
test("internal reviewer separation leaves financial authorisation disabled",()=>{
 const r=checkOperatorReviewer(c,rows,reviewer);
 assert.equal(r.eligibleForNonbindingOperatorReview,true);assert.equal(r.paymentAuthority,false);
 assert.equal(r.decisionAuthority,false);assert.equal(r.partyIdentityVerified,false);
 assert.match(r.evidenceSnapshotSha256,/^[a-f0-9]{64}$/);
});
test("opener, evidence author and incomplete reports are blocked",()=>{
 assert.ok(checkOperatorReviewer(c,rows,owner).blockingGates.includes("reviewer_opened_case"));
 assert.ok(checkOperatorReviewer(c,[...rows.slice(0,2),e(3,"operator_review_note","note.s3",reviewer)],reviewer).blockingGates.includes("reviewer_recorded_evidence"));
 assert.ok(checkOperatorReviewer(c,[e(1,"claim_reported","wrong.claim"),...rows.slice(1)],reviewer).blockingGates.includes("matching_claim_report_missing"));
 assert.ok(checkOperatorReviewer(c,rows.slice(0,2),reviewer).blockingGates.includes("operator_review_note_missing"));
});
test("tampering, duplicates and oversized registers fail closed",()=>{
 assert.throws(()=>checkOperatorReviewer({...c,funds_moved:true},rows,reviewer));
 assert.throws(()=>checkOperatorReviewer(c,[{...rows[0],externally_verified:true}],reviewer));
 assert.throws(()=>checkOperatorReviewer(c,[rows[0],rows[0]],reviewer));
 assert.throws(()=>checkOperatorReviewer(c,Array(MAX_REVIEW_REPORTS+1).fill(rows[0]),reviewer));
});
test("snapshot digest changes after new reports",()=>{
 assert.notEqual(checkOperatorReviewer(c,rows,reviewer).evidenceSnapshotSha256,
 checkOperatorReviewer(c,[...rows,e(4,"appeal_reported","appeal.s3")],reviewer).evidenceSnapshotSha256);
});
