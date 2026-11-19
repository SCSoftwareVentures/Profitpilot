import test from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, sign } from "node:crypto";
import { canonicalApproval, verifyAustralianRelease, REQUIRED_GATES, POLICY } from "../scripts/verify-australian-compliance.js";

const now=Date.parse("2026-11-18T12:00:00.000Z");
function fixture(){
  const counsel=generateKeyPairSync("ed25519"),owner=generateKeyPairSync("ed25519");
  const fp=k=>createHash("sha256").update(k.export({type:"spki",format:"der"})).digest("hex");
  const trust={counselKey:counsel.publicKey,ownerKey:owner.publicKey,counselFingerprint:fp(counsel.publicKey),ownerFingerprint:fp(owner.publicKey)};
  const expected={commit:"a".repeat(40),scopeSha256:"b".repeat(64)};
  const record={policy:POLICY,...expected,approvedAt:"2026-11-18T11:00:00.000Z",expiresAt:"2026-12-18T11:00:00.000Z",gates:REQUIRED_GATES.map((id,i)=>({id,status:"approved",evidenceSha256:createHash("sha256").update("synthetic-"+i).digest("hex")}))};
  const signed=(r=record)=>({record:r,counselSignature:sign(null,canonicalApproval(r),counsel.privateKey).toString("base64"),ownerSignature:sign(null,canonicalApproval(r),owner.privateKey).toString("base64")});
  return {trust,expected,record,signed,counsel,owner};
}
const deny=fn=>assert.throws(fn,/Australian legal release gate denied/);
test("both separately pinned signers and all twelve approvals allow exact synthetic release",()=>{
  const f=fixture();assert.equal(verifyAustralianRelease(f.signed(),f.expected,f.trust,now),true);
});
test("missing, pending, duplicate, reordered or zero-evidence gate cannot be signed as approved",()=>{
  const {record}=fixture();
  deny(()=>canonicalApproval({...record,gates:record.gates.slice(1)}));
  for(const alteration of [{status:"pending"},{id:"AU02"},{evidenceSha256:"0".repeat(64)}]){
    const gates=record.gates.map((g,i)=>i===0?{...g,...alteration}:g);
    deny(()=>canonicalApproval({...record,gates}));
  }
  deny(()=>canonicalApproval({...record,gates:[...record.gates].reverse()}));
  deny(()=>canonicalApproval({...record,notes:"not permitted"}));
});
test("approved bundle denies different commit, configuration, tampering and signature substitution",()=>{
  const f=fixture(),b=f.signed();
  deny(()=>verifyAustralianRelease(b,{...f.expected,commit:"c".repeat(40)},f.trust,now));
  deny(()=>verifyAustralianRelease(b,{...f.expected,scopeSha256:"c".repeat(64)},f.trust,now));
  const changed={...b,record:{...b.record,gates:b.record.gates.map((g,i)=>i===0?{...g,evidenceSha256:"d".repeat(64)}:g)}};
  deny(()=>verifyAustralianRelease(changed,f.expected,f.trust,now));
  deny(()=>verifyAustralianRelease({...b,ownerSignature:b.counselSignature},f.expected,f.trust,now));
  deny(()=>verifyAustralianRelease({...b,ownerSignature:""},f.expected,f.trust,now));
});
test("denies expired, future, excessive duration and malformed timestamps",()=>{
  const f=fixture();
  for(const changes of [
    {expiresAt:"2026-11-18T12:00:00.000Z"},
    {approvedAt:"2026-11-18T12:00:01.000Z"},
    {expiresAt:"2027-03-18T12:00:00.000Z"},
    {expiresAt:"2026-11-18T10:00:00.000Z"}
  ]) deny(()=>verifyAustralianRelease(f.signed({...f.record,...changes}),f.expected,f.trust,now));
  deny(()=>canonicalApproval({...f.record,approvedAt:"2026-02-30T12:00:00.000Z"}));
});
test("denies unpinned keys and a single signer occupying both roles",()=>{
  const f=fixture(),b=f.signed();
  deny(()=>verifyAustralianRelease(b,f.expected,{...f.trust,ownerFingerprint:"f".repeat(64)},now));
  deny(()=>verifyAustralianRelease({...b,ownerSignature:b.counselSignature},f.expected,{...f.trust,ownerKey:f.trust.counselKey,ownerFingerprint:f.trust.counselFingerprint},now));
  deny(()=>verifyAustralianRelease(b,f.expected,{...f.trust,extra:"unexpected"},now));
});
