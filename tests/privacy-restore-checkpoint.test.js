import test from "node:test";
import assert from "node:assert/strict";
import {signCheckpoint,verifyCheckpoint,checkpointDigest,assessBackupInventory,restorePoolOptions} from "../scripts/privacy-restore-checkpoint.js";
const now=Date.parse("2026-11-17T00:00:00Z"),key="ab".repeat(32),deploymentId="profitpilot-ci";
const uuid=n=>n.toString(16).padStart(8,"0")+"-1111-4111-8111-111111111111";
const closure={kind:"closure",id:uuid(1),tenantId:uuid(2),requestId:uuid(3),at:"1794873600.123456",emailErased:true};
const redaction={kind:"redaction",id:uuid(4),tenantId:uuid(2),at:"1794873600.234567"};
const state={markers:[closure,redaction],violations:[]};
const doc=signCheckpoint(state,{key,deploymentId,now});
const opt={key,deploymentId,now,expectedDigest:checkpointDigest(doc)};
test("restore gate accepts all matching markers and rejects missing, changed and inconsistent state",()=>{
 assert.equal(verifyCheckpoint(doc,state,opt).verified,true);
 assert.throws(()=>verifyCheckpoint(doc,{markers:[closure],violations:[]},opt),/missing or has changed/);
 assert.throws(()=>verifyCheckpoint(doc,{markers:[{...closure,emailErased:false},redaction],violations:[]},opt),/missing or has changed/);
 assert.throws(()=>verifyCheckpoint(doc,{...state,violations:[{kind:"closure_state_mismatch"}]},opt),/inconsistent/);
 assert.throws(()=>signCheckpoint({...state,markers:[closure,closure]},{key,deploymentId,now}),/Duplicate/);
});
test("restore gate rejects tampering, stale checkpoints, wrong deployment and wrong digest",()=>{
 const changed=structuredClone(doc);changed.payload.markers=[];
 assert.throws(()=>verifyCheckpoint(changed,state,{...opt,expectedDigest:checkpointDigest(changed)}),/signature/);
 assert.throws(()=>verifyCheckpoint(doc,state,{...opt,expectedDigest:"00".repeat(32)}),/digest/);
 assert.throws(()=>verifyCheckpoint(doc,state,{...opt,now:now+25*3600000}),/stale/);
 assert.throws(()=>verifyCheckpoint(doc,state,{...opt,deploymentId:"other-deployment"}),/deployment/);
 assert.throws(()=>verifyCheckpoint(doc,state,{...opt,key:"cd".repeat(32)}),/signature/);
});
test("backup expiry is reviewed, never automatically deleted; legal holds must have evidence",()=>{
 const b={id:"backup-1",createdAt:"2026-10-01T00:00:00Z",expiresAt:"2026-10-31T00:00:00Z",encrypted:true,legalHold:false};
 const result=assessBackupInventory([b,{...b,id:"backup-2",legalHold:true},{...b,id:"backup-3",legalHold:true,holdReference:"approved-hold"}],{now,maxRetentionDays:30});
 assert.deepEqual(result.map(x=>x.expiryReviewDue),[true,false,false]);
 assert.deepEqual(result[0].issues,["expiry_due_or_overdue"]);
 assert.deepEqual(result[1].issues,["missing_hold_evidence"]);
 assert.deepEqual(result[2].issues,[]);
 assert.throws(()=>assessBackupInventory([b],{now,maxRetentionDays:0}),/policy/);
});

test("operator recovery connection requires verified TLS without URL overrides",()=>{
 assert.deepEqual(restorePoolOptions("postgresql://operator:placeholder@db.example.invalid/profitpilot").ssl,{rejectUnauthorized:true});
 for(const url of ["postgres://operator@db.example.invalid/profitpilot?sslmode=disable","postgres://operator@db.example.invalid/profitpilot?sslmode=require","postgresql://operator@db.example.invalid/profitpilot?sslrootcert=anything","https://db.example.invalid/profitpilot","not-a-url"])assert.throws(()=>restorePoolOptions(url),/PostgreSQL URL/);
});
