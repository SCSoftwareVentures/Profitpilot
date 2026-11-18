import test from "node:test";
import assert from "node:assert/strict";
import {createHash,generateKeyPairSync,randomUUID,sign} from "node:crypto";
import {canonicalDisposalEvidence,inventoryDigest,dispositionDigest,verifyBackupDisposition} from "../scripts/verify-backup-disposition.js";
const hash=x=>createHash("sha256").update(x).digest("hex"),roles=["counsel","custodian","assessor","owner"],now=Date.parse("2035-01-03T12:00:00.000Z");
const keys=Object.fromEntries(roles.map(role=>[role,generateKeyPairSync("ed25519")]));
function fixture(){
 const inventory=[{copyId:"1".repeat(64),kind:"backup",contentSha256:hash("synthetic-backup"),retainThrough:"2035-01-01"},{copyId:"2".repeat(64),kind:"replica",contentSha256:hash("synthetic-replica"),retainThrough:"2035-01-01"}];
 const plan=inventory.map(x=>({copyId:x.copyId,method:"provider_verified_deletion",authoritySha256:hash("synthetic authority "+x.copyId)}));
 const expected={tenantId:randomUUID(),allocationRunId:randomUUID(),receiptSha256:hash("receipt"),orderId:randomUUID(),inventorySha256:inventoryDigest(inventory),dispositionSha256:dispositionDigest(plan),checkedOn:"2035-01-02"};
 const evidence=new Map();
 const receipts=plan.map(x=>{const b=Buffer.from("synthetic evidence "+x.copyId);evidence.set(hash(b),b);return {copyId:x.copyId,method:x.method,completedAt:"2035-01-02T12:00:00.000Z",evidenceSha256:hash(b),status:"disposition-evidenced"};});
 const record={format:"profitpilot-backup-disposition-evidence-v1",...expected,issuedAt:"2035-01-03T10:00:00.000Z",expiresAt:"2035-01-04T10:00:00.000Z",receipts};
 const trust=Object.fromEntries(roles.map(role=>[role,{publicKey:keys[role].publicKey,fingerprint:hash(keys[role].publicKey.export({type:"spki",format:"der"}))}]));
 const signed=r=>({record:r,signatures:Object.fromEntries(roles.map(role=>[role,sign(null,canonicalDisposalEvidence(r),keys[role].privateKey).toString("base64")]))});
 return {expected,inventory,plan,evidence,trust,now,bundle:signed(record),resign(){this.bundle=signed(this.bundle.record);}};
}
test("all exact copies and four separately pinned signatures verify evidence, never disposal authority",()=>{
 const f=fixture();assert.deepEqual(verifyBackupDisposition(f),{status:"signed-evidence-verified",copies:2,authorizesDisposal:false,provesPhysicalErasure:false});
});
const cases=[
 ["other tenant",f=>{f.expected.tenantId=randomUUID();}],
 ["other allocation",f=>{f.expected.allocationRunId=randomUUID();}],
 ["other receipt",f=>{f.expected.receiptSha256=hash("other");}],
 ["other work order",f=>{f.expected.orderId=randomUUID();}],
 ["wrong approved inventory",f=>{f.expected.inventorySha256=hash("other");}],
 ["wrong approved disposition",f=>{f.expected.dispositionSha256=hash("other");}],
 ["missing copy",f=>{f.inventory.pop();}],
 ["duplicate copy",f=>{f.inventory[1]=f.inventory[0];}],
 ["reordered copies",f=>{f.inventory.reverse();}],
 ["changed retention date",f=>{f.inventory[0].retainThrough="2035-01-02";}],
 ["changed plan method",f=>{f.plan[0].method="media_sanitisation";}],
 ["missing document",f=>{f.evidence.delete(f.bundle.record.receipts[0].evidenceSha256);}],
 ["substituted document",f=>{f.evidence.set(f.bundle.record.receipts[0].evidenceSha256,Buffer.from("tampered"));}],
 ["unexpected document",f=>{f.evidence.set(hash("extra"),Buffer.from("extra"));}],
 ["wrong signer",f=>{f.bundle.signatures.assessor=f.bundle.signatures.owner;}],
 ["duplicate trust",f=>{f.trust.assessor=f.trust.owner;}],
 ["wrong pin",f=>{f.trust.owner.fingerprint=hash("other");}],
 ["expired statement",f=>{f.now=Date.parse("2035-01-04T10:00:00.000Z");}],
 ["future approval",f=>{f.now=Date.parse("2035-01-03T09:00:00.000Z");}],
 ["retention is inclusive even if signed",f=>{f.bundle.record.receipts[0].completedAt="2035-01-01T23:59:59.999Z";f.resign();}],
 ["completed after signature",f=>{f.bundle.record.receipts[0].completedAt="2035-01-03T11:00:00.000Z";f.resign();}],
 ["receipt method mismatch even if signed",f=>{f.bundle.record.receipts[0].method="media_sanitisation";f.resign();}],
 ["missing receipt even if signed",f=>{f.bundle.record.receipts.pop();f.resign();}],
 ["approval window too wide",f=>{f.bundle.record.expiresAt="2035-01-05T10:00:00.000Z";f.resign();}],
 ["unsigned scope modification",f=>{f.bundle.record.checkedOn="2035-01-01";f.expected.checkedOn="2035-01-01";}],
 ["unknown record field",f=>{f.bundle.record.authorizesDisposal=true;}]
];
for(const [name,change] of cases)test(name,()=>{const f=fixture();change(f);assert.throws(()=>verifyBackupDisposition(f));});
