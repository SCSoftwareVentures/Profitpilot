import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,createHash,sign} from "node:crypto";
import {canonicalApproval,REQUIRED_GATES,POLICY} from "../scripts/verify-australian-compliance.js";
import {canonicalProductionAcceptance,legalApprovalDigest,verifyProductionAcceptance,RELEASE_GATES} from "../scripts/verify-production-acceptance.js";
const now=Date.parse("2026-11-18T12:00:00.000Z"),hash=x=>createHash("sha256").update(x).digest("hex"),roles=["counsel","assessor","operations","owner"];
function fixture(){
 const keys=Object.fromEntries(roles.map(r=>[r,generateKeyPairSync("ed25519")]));
 const trust=Object.fromEntries(roles.map(r=>[r,{key:keys[r].publicKey,fingerprint:hash(keys[r].publicKey.export({type:"spki",format:"der"}))}]));
 const expected={commit:"a".repeat(40),scopeSha256:hash("synthetic-scope"),manifestSha256:hash("synthetic-manifest")};
 const legalRecord={policy:POLICY,commit:expected.commit,scopeSha256:expected.scopeSha256,approvedAt:"2026-11-18T10:00:00.000Z",expiresAt:"2026-12-18T10:00:00.000Z",gates:REQUIRED_GATES.map(id=>({id,status:"approved",evidenceSha256:hash(id)}))};
 const signed=(value,role)=>sign(null,value,keys[role].privateKey).toString("base64");
 const legal={record:legalRecord,counselSignature:signed(canonicalApproval(legalRecord),"counsel"),ownerSignature:signed(canonicalApproval(legalRecord),"owner")};
 const record={format:"profitpilot-production-acceptance-v1",...expected,legalSha256:legalApprovalDigest(legal),approvedAt:"2026-11-18T11:00:00.000Z",expiresAt:"2026-12-01T11:00:00.000Z",gates:RELEASE_GATES.map(id=>({id,status:"approved",evidenceSha256:hash(id)}))};
 const bundle=(r=record,l=legal)=>({legal:l,record:r,signatures:Object.fromEntries(roles.slice(1).map(role=>[role,signed(canonicalProductionAcceptance(r),role)]))});
 return {trust,expected,record,legal,bundle};
}
test("production gate requires both legal and separately pinned operational and security approvals",()=>{
 const f=fixture();assert.equal(verifyProductionAcceptance(f.bundle(),f.expected,f.trust,now),true);
 const b=f.bundle();
 for(const k of ["commit","scopeSha256","manifestSha256"])assert.throws(()=>verifyProductionAcceptance(b,{...f.expected,[k]:k==="commit"?"b".repeat(40):hash("other")},f.trust,now));
 assert.throws(()=>verifyProductionAcceptance({...b,signatures:{...b.signatures,assessor:b.signatures.owner}},f.expected,f.trust,now));
 assert.throws(()=>verifyProductionAcceptance(b,f.expected,{...f.trust,assessor:f.trust.owner},now));
 assert.throws(()=>verifyProductionAcceptance({...b,legal:{...b.legal,counselSignature:b.legal.ownerSignature}},f.expected,f.trust,now));
 assert.throws(()=>verifyProductionAcceptance({...b,record:{...b.record,manifestSha256:hash("substitution")}},f.expected,f.trust,now));
});
test("approved evidence is mandatory, distinct, ordered, fresh, and bounded by legal approval",()=>{
 const f=fixture();const g=f.record.gates;
 for(const gates of [g.slice(1),[...g].reverse(),g.map((v,i)=>i===0?{...v,status:"pending"}:v),g.map(v=>({...v,evidenceSha256:g[0].evidenceSha256}))])assert.throws(()=>canonicalProductionAcceptance({...f.record,gates}));
 for(const changes of [{expiresAt:"2026-11-18T12:00:00.000Z"},{approvedAt:"2026-11-18T12:00:01.000Z"},{approvedAt:"2026-11-18T09:59:00.000Z"},{expiresAt:"2026-12-30T11:00:00.000Z"},{legalSha256:hash("replacement")}])assert.throws(()=>verifyProductionAcceptance(f.bundle({...f.record,...changes}),f.expected,f.trust,now));
 assert.throws(()=>verifyProductionAcceptance(f.bundle(),f.expected,f.trust,Date.parse("2026-12-20T12:00:00.000Z")));
});
