import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,randomUUID,randomBytes} from "node:crypto";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,readdirSync,rmSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {loadRecoveryApproverPolicy,recoveryApprovalBytes,signRecoveryApprovalRequest,
 verifyRecoveryApproval,signRecoveryAudit,verifyRecoveryAudit} from "../src/securepay-recovery-controls.js";
import {runSyntheticRehearsal,runAuditVerification} from "../scripts/securepay-restore-rehearsal.mjs";

const pemPublic=key=>key.export({type:"spki",format:"pem"});
const pemPrivate=key=>key.export({type:"pkcs8",format:"pem"});
const pair=()=>generateKeyPairSync("ed25519");
const custodian=pair(),reviewer=pair(),auditor=pair();
const tenant=randomUUID(),operator=randomUUID(),ticket="ci.s11-3.recovery";
const manifest={format:"profitpilot.s11.3.approvers.v1",approvers:[
 {role:"custodian",keyId:"custody-persona",publicKeyPem:pemPublic(custodian.publicKey)},
 {role:"privacy-reviewer",keyId:"privacy-persona",publicKeyPem:pemPublic(reviewer.publicKey)}
]};
const policy=loadRecoveryApproverPolicy(manifest);
function approval(ticketRef=ticket,changes={}){
 const request={version:"profitpilot.s11.3.request.v1",tenantId:tenant,operatorId:operator,
  ticketRef,requestId:randomUUID(),issuedAt:new Date(Date.now()-1000).toISOString(),
  expiresAt:new Date(Date.now()+1800000).toISOString(),
  purpose:"synthetic-offline-integrity-rehearsal",legalHoldState:"no_declared_hold",
  retentionStatus:"unverified_review_only",syntheticOnly:true,...changes};
 return {request,signatures:[
  {role:"custodian",keyId:"custody-persona",signature:signRecoveryApprovalRequest(request,custodian.privateKey)},
  {role:"privacy-reviewer",keyId:"privacy-persona",signature:signRecoveryApprovalRequest(request,reviewer.privateKey)}
 ]};
}
const scope={tenantId:tenant,operatorId:operator,ticketRef:ticket};
test("S11.3 two independent pinned keys authorise narrow synthetic-only scope",()=>{
 const bundle=approval();
 const verified=verifyRecoveryApproval(bundle,policy,scope);
 assert.equal(verified.requestId,bundle.request.requestId);
 assert.equal(verified.signerIds.length,2);
 assert.equal(verified.legalHoldState,"no_declared_hold");
 assert.equal(verified.proofDigest.length,64);
 assert.equal(Buffer.isBuffer(recoveryApprovalBytes(bundle.request)),true);
});
test("S11.3 denies wrong tenant/operator/ticket, missing, duplicated and altered signatures",()=>{
 const b=approval();
 for(const different of [{tenantId:randomUUID(),operatorId:operator,ticketRef:ticket},
  {tenantId:tenant,operatorId:randomUUID(),ticketRef:ticket},
  {tenantId:tenant,operatorId:operator,ticketRef:"different-ticket"}])
  assert.throws(()=>verifyRecoveryApproval(b,policy,different));
 assert.throws(()=>verifyRecoveryApproval({...b,signatures:[b.signatures[0]]},policy,scope));
 assert.throws(()=>verifyRecoveryApproval({...b,signatures:[b.signatures[0],b.signatures[0]]},policy,scope));
 assert.throws(()=>verifyRecoveryApproval({...b,request:{...b.request,tenantId:randomUUID()}},policy,scope));
 const corrupted={...b,signatures:[{...b.signatures[0],signature:signRecoveryApprovalRequest(b.request,reviewer.privateKey)},b.signatures[1]]};
 assert.throws(()=>verifyRecoveryApproval(corrupted,policy,scope));
 assert.throws(()=>loadRecoveryApproverPolicy({...manifest,approvers:[
  manifest.approvers[0],{...manifest.approvers[1],publicKeyPem:manifest.approvers[0].publicKeyPem}]}));
 assert.throws(()=>loadRecoveryApproverPolicy({...manifest,approvers:[
  manifest.approvers[0],{...manifest.approvers[0]}]}));
});
test("S11.3 approval window, declared hold, unknown hold and retention claims block",()=>{
 for(const changes of [
  {legalHoldState:"active_hold"},{legalHoldState:"unknown"},
  {retentionStatus:"legally_cleared"},{syntheticOnly:false},
  {purpose:"export_original_bytes"},
  {issuedAt:new Date(Date.now()+120000).toISOString(),expiresAt:new Date(Date.now()+1200000).toISOString()},
  {issuedAt:new Date(Date.now()-7200000).toISOString(),expiresAt:new Date(Date.now()+1800000).toISOString()},
  {issuedAt:new Date(Date.now()-60000).toISOString(),expiresAt:new Date(Date.now()-1000).toISOString()},
  {expiresAt:new Date(Date.now()+7200000).toISOString()}
 ]){
  const b=approval(ticket,changes);
  assert.throws(()=>verifyRecoveryApproval(b,policy,scope),JSON.stringify(changes));
 }
});
const event=(sequence,approvalId=randomUUID())=>({
 schema:"profitpilot.s11.3.restore-audit.v1",sequence,recordedAt:new Date().toISOString(),
 tenantId:tenant,operatorReportedId:operator,operatorReportedTicket:ticket,
 approvalRequestId:approvalId,approvalProofDigest:"a".repeat(64),
 approvalKeyIds:["custody-persona","privacy-persona"],legalHoldState:"no_declared_hold",
 operatorIdentityIndependentlyVerified:false,approverIdentityIndependentlyVerified:false,
 externallyWitnessed:false,primaryDbMutated:false,plaintextExported:false,
 outcome:"rejected",reason:"offline_rehearsal_denied",recovery:null
});
test("S11.3 signed audit chain detects event edits, missing links and forged signatures",()=>{
 const first=signRecoveryAudit(event(1),null,auditor.privateKey);
 const digest1=verifyRecoveryAudit(first,auditor.publicKey,null);
 const second=signRecoveryAudit(event(2),digest1,auditor.privateKey);
 const digest2=verifyRecoveryAudit(second,auditor.publicKey,digest1);
 assert.equal(digest2.length,64);
 assert.throws(()=>verifyRecoveryAudit(second,auditor.publicKey,null));
 assert.throws(()=>verifyRecoveryAudit({...first,event:{...first.event,operatorReportedTicket:"spoof.ticket"}},auditor.publicKey,null));
 assert.throws(()=>verifyRecoveryAudit({...first,signature:signRecoveryApprovalRequest(approval().request,custodian.privateKey)},auditor.publicKey,null));
 assert.throws(()=>verifyRecoveryAudit(first,custodian.publicKey,null));
 assert.throws(()=>signRecoveryAudit({...event(1),plaintextExported:true},null,auditor.privateKey));
});
test("S11.3 private signed audit of denied attempts, replay refusal and independent head check",async()=>{
 const dir=mkdtempSync(join(tmpdir(),"sp-s11-3-"));
 const privateFile=(name,contents)=>{const f=join(dir,name);writeFileSync(f,contents,{mode:0o600});return f;};
 try{
  const auditDir=join(dir,"audit");mkdirSync(auditDir,{mode:0o700});
  const dbFile=privateFile("db-url","postgresql://unsafe@remote.invalid/not_a_restore_db");
  const approvalFile=privateFile("approval.json",JSON.stringify(approval()));
  const policyFile=privateFile("approvers.json",JSON.stringify(manifest));
  const auditPrivate=privateFile("audit-private.pem",pemPrivate(auditor.privateKey));
  const auditPublic=privateFile("audit-public.pem",pemPublic(auditor.publicKey));
  const env={NODE_ENV:"test",PROFITPILOT_PROFILE:"prototype",
   SECUREPAY_OFFLINE_RECOVERY_MODE:"synthetic-rehearsal",
   SECUREPAY_RECOVERY_APPROVERS_FILE:policyFile,SECUREPAY_RECOVERY_APPROVAL_FILE:approvalFile,
   SECUREPAY_RECOVERY_AUDIT_PRIVATE_KEY_FILE:auditPrivate,
   SECUREPAY_RECOVERY_AUDIT_PUBLIC_KEY_FILE:auditPublic};
  const args=["rehearse",tenant,dbFile,auditDir,operator,ticket];
  await assert.rejects(()=>runSyntheticRehearsal(args,env),/rejected/);
  const saved=JSON.parse(readFileSync(join(auditDir,"s11-3-000001.json"),"utf8"));
  assert.equal(saved.event.outcome,"rejected");
  assert.equal(saved.event.approvalKeyIds.length,2);
  assert.equal(saved.event.legalHoldState,"no_declared_hold");
  assert.equal(saved.event.operatorIdentityIndependentlyVerified,false);
  assert.equal(JSON.stringify(saved).includes("remote.invalid"),false);
  let digest=verifyRecoveryAudit(saved,auditor.publicKey,null);
  const verified=runAuditVerification(["verify-audit",auditDir,auditPublic,digest]);
  assert.equal(verified.verifiedSignedRecords,1);
  await assert.rejects(()=>runSyntheticRehearsal(args,env),/rejected/);
  const second=JSON.parse(readFileSync(join(auditDir,"s11-3-000002.json"),"utf8"));
  assert.equal(second.event.outcome,"rejected");
  assert.equal(second.event.approvalRequestId,saved.event.approvalRequestId);
  const secondDigest=verifyRecoveryAudit(second,auditor.publicKey,digest);
  assert.throws(()=>runAuditVerification(["verify-audit",auditDir,auditPublic,digest]),/head differs/);
  assert.equal(runAuditVerification(["verify-audit",auditDir,auditPublic,secondDigest]).verifiedSignedRecords,2);
  const files=readdirSync(auditDir);
  assert.equal(files.length,2);
  const tampered={...saved,event:{...saved.event,operatorReportedTicket:"tampered.ticket"}};
  writeFileSync(join(auditDir,"s11-3-000001.json"),JSON.stringify(tampered),{mode:0o600});
  await assert.rejects(()=>runSyntheticRehearsal(args,env));
  assert.equal(readdirSync(auditDir).length,2);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
