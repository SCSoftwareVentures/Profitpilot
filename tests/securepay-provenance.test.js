import test from "node:test";
import assert from "node:assert/strict";
import {validProvenanceRequest,reportedMetadataDigest,sameReportedMetadata} from "../src/securepay-provenance.js";
const b={clientRequestId:"11111111-1111-4111-8111-111111111111",reportedOrigin:"reported_customer",
 acquisitionMethod:"operator_relay",sourceReference:"opaque.source.001"};
const receipt={tenantId:"22222222-2222-4222-8222-222222222222",
 caseId:"33333333-3333-4333-8333-333333333333",
 evidenceId:"44444444-4444-4444-8444-444444444444",
 actorId:"55555555-5555-4555-8555-555555555555",
 jobReference:"job.synthetic.001",evidenceType:"claim_reported",evidenceReference:"claim.synthetic.001",
 reportedOrigin:b.reportedOrigin,acquisitionMethod:b.acquisitionMethod,sourceReference:b.sourceReference};
test("synthetic provenance metadata fields are exact, bounded, and cannot claim verified origin",()=>{
 assert.equal(validProvenanceRequest(b),true);
 for(const bad of [{...b,originVerified:true},{...b,recordedBy:receipt.actorId},{...b,reportedOrigin:"verified_customer"},
 {...b,sourceReference:"<pii>"},{...b,sourceReference:"a".repeat(121)},{...b,acquisitionMethod:"trusted_upload"},null,[],{}])
  assert.equal(validProvenanceRequest(bad),false);
});
test("metadata fingerprint is deterministic, scoped, and not a document hash",()=>{
 const a=reportedMetadataDigest(receipt);
 assert.match(a,/^[a-f0-9]{64}$/);assert.equal(a,reportedMetadataDigest(receipt));
 assert.notEqual(a,reportedMetadataDigest({...receipt,sourceReference:"other.source"}));
 assert.notEqual(a,reportedMetadataDigest({...receipt,tenantId:"66666666-6666-4666-8666-666666666666"}));
 assert.notEqual(a,reportedMetadataDigest({...receipt,actorId:"77777777-7777-4777-8777-777777777777"}));
 assert.throws(()=>reportedMetadataDigest({...receipt,reportedOrigin:"verified_customer"}),TypeError);
});
test("idempotent metadata comparison rejects changed origin and acquisition",()=>{
 const row={reported_origin:b.reportedOrigin,acquisition_method:b.acquisitionMethod,source_reference:b.sourceReference};
 assert.equal(sameReportedMetadata(row,b),true);
 assert.equal(sameReportedMetadata(row,{...b,reportedOrigin:"reported_business"}),false);
 assert.equal(sameReportedMetadata(row,{...b,acquisitionMethod:"unknown"}),false);
});
