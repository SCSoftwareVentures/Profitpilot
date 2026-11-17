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

test("restore checkpoint retains correction receipts without personal email addresses",()=>{
 const c={kind:"local_email_correction",id:uuid(5),tenantId:uuid(2),userId:uuid(6),at:"1794873600.345678"};
 const st={markers:[...state.markers,c],violations:[]};
 const signed=signCheckpoint(st,{key,deploymentId,now});
 const options={...opt,expectedDigest:checkpointDigest(signed)};
 assert.equal(verifyCheckpoint(signed,st,options).requiredMarkers,3);
 assert.throws(()=>verifyCheckpoint(signed,state,options),/missing or has changed/);
 assert.equal(JSON.stringify(signed).includes("@"),false);
});

test("account-wide revocation evidence survives repeated incidents without disclosing tokens",()=>{
 const first={kind:"account_session_revocation",id:uuid(7),userId:uuid(8),at:"1794873600"};
 const second={...first,id:uuid(9),at:"1794873610"};
 const original={markers:[first],violations:[]};
 const latest={markers:[first,second],violations:[]};
 const oldDoc=signCheckpoint(original,{key,deploymentId,now});
 const latestDoc=signCheckpoint(latest,{key,deploymentId,now});
 const latestOpt={...opt,expectedDigest:checkpointDigest(latestDoc)};
 assert.equal(verifyCheckpoint(oldDoc,latest,{...opt,expectedDigest:checkpointDigest(oldDoc)}).verified,true);
 assert.equal(verifyCheckpoint(latestDoc,latest,latestOpt).requiredMarkers,2);
 assert.throws(()=>verifyCheckpoint(latestDoc,original,latestOpt),/missing or has changed/);
 assert.throws(()=>verifyCheckpoint(latestDoc,{markers:[first,{...second,at:"1794873601"}],violations:[]},latestOpt),/missing or has changed/);
 assert.throws(()=>verifyCheckpoint(latestDoc,{...latest,violations:[{kind:"revoked_session_reinstated"}]},latestOpt),/inconsistent/);
 for(const at of ["-1","1.5","Infinity","12345678901234567"])assert.throws(()=>signCheckpoint({markers:[{...first,at}],violations:[]},{key,deploymentId,now}),/Invalid session revocation marker/);
 assert.equal(JSON.stringify(latestDoc).includes("tenantId"),false);
});

test("individual revocation receipts detect rollback and fingerprint or expiry substitution",()=>{
 const receipt={kind:"individual_session_revocation",id:uuid(10),tokenFingerprint:"de".repeat(32),at:"1794873600.123456",expiresAt:"1794873900.000000"};
 const st={markers:[receipt],violations:[]};
 const signed=signCheckpoint(st,{key,deploymentId,now});
 const options={...opt,expectedDigest:checkpointDigest(signed)};
 assert.equal(verifyCheckpoint(signed,st,options).requiredMarkers,1);
 assert.throws(()=>verifyCheckpoint(signed,{markers:[],violations:[]},options),/missing or has changed/);
 for(const patch of [{tokenFingerprint:"ef".repeat(32)},{expiresAt:"1794873901.000000"},{at:"1794873601.123456"}]){
  assert.throws(()=>verifyCheckpoint(signed,{markers:[{...receipt,...patch}],violations:[]},options),/missing or has changed/);
 }
 assert.throws(()=>verifyCheckpoint(signed,{...st,violations:[{kind:"individually_revoked_session_reinstated"}]},options),/inconsistent/);
 assert.throws(()=>signCheckpoint({markers:[{...receipt,tokenFingerprint:"raw-token"}],violations:[]},{key,deploymentId,now}),/Invalid individual session revocation marker/);
 assert.equal(JSON.stringify(signed).includes("subject"),false);
});

test("containment and recovery checkpoints independently bind incident evidence",()=>{
 const contained={kind:"account_contained",id:uuid(11),userId:uuid(12),at:"1794873600.1",evidence:"ab".repeat(32)};
 const recovered={...contained,kind:"account_recovered",at:"1794873601.1",evidence:"cd".repeat(32)};
 const full={markers:[contained,recovered],violations:[]};
 const signed=signCheckpoint(full,{key,deploymentId,now});
 const options={...opt,expectedDigest:checkpointDigest(signed)};
 assert.equal(verifyCheckpoint(signed,full,options).requiredMarkers,2);
 assert.throws(()=>verifyCheckpoint(signed,{markers:[contained],violations:[]},options),/missing or has changed/);
 assert.throws(()=>verifyCheckpoint(signed,{markers:[contained,{...recovered,evidence:"ef".repeat(32)}],violations:[]},options),/missing or has changed/);
 assert.throws(()=>verifyCheckpoint(signed,{...full,violations:[{kind:"account_containment_state_mismatch"}]},options),/inconsistent/);
});

test("audit prefixes and retired signing keys are independently bound into recovery checkpoints",()=>{
 const anchor={kind:"audit_restore_anchor",id:uuid(13),tenantId:uuid(14),position:"9",eventHash:"aa".repeat(32),at:"1794873600.123456"};
 const retired={kind:"signing_key_retired",id:"bb".repeat(32),fingerprint:"cc".repeat(32),at:"1794873601.123456"};
 const st={markers:[anchor,retired],violations:[]};
 const signed=signCheckpoint(st,{key,deploymentId,now});
 const options={...opt,expectedDigest:checkpointDigest(signed)};
 assert.equal(verifyCheckpoint(signed,st,options).requiredMarkers,2);
 assert.throws(()=>verifyCheckpoint(signed,{markers:[anchor],violations:[]},options),/missing or has changed/);
 assert.throws(()=>verifyCheckpoint(signed,{markers:[{...anchor,eventHash:"dd".repeat(32)},retired],violations:[]},options),/missing or has changed/);
 assert.throws(()=>verifyCheckpoint(signed,{...st,violations:[{kind:"audit_chain_inconsistent"}]},options),/inconsistent/);
 for(const position of ["0","-1","1.5","9223372036854775808"])assert.throws(()=>signCheckpoint({markers:[{...anchor,position}],violations:[]},{key,deploymentId,now}),/Invalid audit anchor/);
 assert.throws(()=>signCheckpoint({markers:[{...retired,fingerprint:"raw-secret"}],violations:[]},{key,deploymentId,now}),/Invalid retired signing key/);
 assert.equal(verifyCheckpoint(signed,{markers:[anchor,retired,{...anchor,id:uuid(15),position:"10",eventHash:"ef".repeat(32)}],violations:[]},options).verified,true);
});
