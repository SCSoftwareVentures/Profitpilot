import test from "node:test";
import assert from "node:assert/strict";
import {createHash,randomBytes,randomUUID} from "node:crypto";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,readdirSync,rmSync,symlinkSync,chmodSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {sealCustodyBytes} from "../src/securepay-encrypted-custody.js";
import {verifyRestoredCustodyRow,summarizeRestoredCustodyRows} from "../src/securepay-offline-recovery.js";
import {runSyntheticRehearsal} from "../scripts/securepay-restore-rehearsal.mjs";

const hash=x=>createHash("sha256").update(x).digest("hex");
const tenant=randomUUID();
const oldKey={keyId:"key-2026-old",cipherKey:randomBytes(32),macKey:randomBytes(32)};
const activeKey={keyId:"key-2026-new",cipherKey:randomBytes(32),macKey:randomBytes(32)};
const ring={mode:"mounted-keyring",active:activeKey,byId:new Map([[oldKey.keyId,oldKey],[activeKey.keyId,activeKey]])};
const bytes=Buffer.from("S11.2 harmless synthetic offline recovery receipt.");

function makeRow(key=oldKey){
 const context={tenantId:tenant,caseId:randomUUID(),evidenceId:randomUUID(),
  clientRequestId:randomUUID(),actorId:randomUUID(),sha256:hash(bytes),byteCount:bytes.length,
  mediaType:"text/plain",keyId:key.keyId};
 const sealed=sealCustodyBytes(bytes,context,key);
 return {id:randomUUID(),tenant_id:tenant,case_id:context.caseId,evidence_id:context.evidenceId,
  client_request_id:context.clientRequestId,received_by:context.actorId,
  sha256:context.sha256,byte_count:context.byteCount,media_type:context.mediaType,
  scan_status:"scanner_reported_clean",scan_observed_at:new Date(sealed.observedAt),
  scanner_attestation_mac:sealed.attestationMac,encryption_algorithm:"aes-256-gcm",
  key_id:key.keyId,aad_sha256:sealed.aadSha256,ciphertext_sha256:sealed.ciphertextSha256,
  ciphertext:sealed.ciphertext,nonce:sealed.nonce,auth_tag:sealed.tag,
  case_synthetic:true,case_funds_moved:false,evidence_externally_verified:false,
  origin_verified:false,source_identity_verified:false,independent_scanner_verified:false,
  independent_custody_verified:false,retention_policy_enforced:false,
  decision_authority:false,payment_authority:false};
}
test("S11.2 restored cryptographic validation is bounded, deterministic and does not return plaintext",()=>{
 const old=makeRow(oldKey),current=makeRow(activeKey);
 const validated=verifyRestoredCustodyRow(old,ring,tenant);
 assert.equal(validated.sha256,hash(bytes));
 assert.equal(Object.hasOwn(validated,"ciphertext"),false);
 assert.equal(Object.hasOwn(validated,"plaintext"),false);
 const a=summarizeRestoredCustodyRows([old,current],ring,tenant);
 const b=summarizeRestoredCustodyRows([current,old],ring,tenant);
 assert.deepEqual(a,b);
 assert.equal(a.verifiedCount,2);
 assert.equal(a.plaintextExposed,false);
 assert.equal(a.operatorScanIndependent,false);
 assert.equal(a.paymentAuthority,false);
 assert.equal(JSON.stringify(a).includes(bytes.toString()),false);
 assert.equal(JSON.stringify(a).includes(oldKey.cipherKey.toString("hex")),false);
});
test("S11.2 rejects wrong/missing historical keys and tampered cryptographic bytes",()=>{
 const row=makeRow(oldKey);
 assert.throws(()=>verifyRestoredCustodyRow(row,{...ring,byId:new Map([[activeKey.keyId,activeKey]])},tenant),/key unavailable/);
 const wrong={...oldKey,macKey:randomBytes(32)};
 assert.throws(()=>verifyRestoredCustodyRow(row,{...ring,byId:new Map([[wrong.keyId,wrong]])},tenant),/MAC invalid/);
 for(const field of ["ciphertext","nonce","auth_tag"]){
  const updated=Buffer.from(row[field]);updated[0]^=1;
  assert.throws(()=>verifyRestoredCustodyRow({...row,[field]:updated},ring,tenant));
 }
 assert.throws(()=>verifyRestoredCustodyRow({...row,scanner_attestation_mac:"a".repeat(64)},ring,tenant));
 assert.throws(()=>verifyRestoredCustodyRow({...row,sha256:"b".repeat(64)},ring,tenant));
 assert.throws(()=>verifyRestoredCustodyRow({...row,tenant_id:randomUUID()},ring,tenant));
});
test("S11.2 rejects non-synthetic, financial, corrupt, missing and cross-tenant receipts",()=>{
 const row=makeRow();
 const invalid=[
  {...row,case_synthetic:false},{...row,case_funds_moved:true},
  {...row,evidence_externally_verified:true},{...row,payment_authority:true},
  {...row,decision_authority:true},{...row,independent_custody_verified:true},
  {...row,retention_policy_enforced:true},{...row,encryption_algorithm:"aes-128-gcm"},
  {...row,scan_status:"unavailable"},{...row,byte_count:0},
  {...row,ciphertext:Buffer.alloc(524289)},{...row,auth_tag:"not-a-buffer"},
  {...row,nonce:Buffer.alloc(10)}
 ];
 for(const bad of invalid)assert.throws(()=>verifyRestoredCustodyRow(bad,ring,tenant));
 assert.throws(()=>verifyRestoredCustodyRow(row,ring,randomUUID()));
 assert.throws(()=>summarizeRestoredCustodyRows([],ring,tenant));
 assert.throws(()=>summarizeRestoredCustodyRows(Array(65).fill(row),ring,tenant));
 assert.throws(()=>summarizeRestoredCustodyRows([row,row],ring,tenant),/Duplicate/);
});
test("S11.2 rejected offline attempt writes private audit metadata, not secrets or plaintext",async()=>{
 const dir=mkdtempSync(join(tmpdir(),"sp-restore-test-"));
 try{
  const auditDir=join(dir,"audit");mkdirSync(auditDir,{mode:0o700});
  const dbFile=join(dir,"url");writeFileSync(dbFile,"postgresql://unsafe@remote.invalid/live_db",{mode:0o600});
  const actor=randomUUID();
  const args=["rehearse",tenant,dbFile,auditDir,actor,"ci.restore.rehearsal"];
  const env={PROFITPILOT_PROFILE:"prototype",SECUREPAY_OFFLINE_RECOVERY_MODE:"synthetic-rehearsal",NODE_ENV:"test"};
  await assert.rejects(()=>runSyntheticRehearsal(args,env),/Offline synthetic recovery rejected/);
  const files=readdirSync(auditDir);
  assert.equal(files.length,1);
  const contents=readFileSync(join(auditDir,files[0]),"utf8");
  const attempt=JSON.parse(contents);
  assert.equal(attempt.outcome,"rejected");
  assert.equal(attempt.operatorIdentityIndependentlyVerified,false);
  assert.equal(attempt.plaintextExported,false);
  assert.equal(attempt.primaryDbMutated,false);
  assert.equal(attempt.reason,"offline_rehearsal_denied");
  assert.equal(contents.includes("remote.invalid"),false);
  assert.equal(contents.includes(bytes.toString()),false);
  assert.equal(contents.includes("cipherKey"),false);
  await assert.rejects(()=>runSyntheticRehearsal(args,{...env,PROFITPILOT_PROFILE:"protected"}),/synthetic-only/);
  assert.equal(readdirSync(auditDir).length,1);
  const symbolic=join(dir,"audit-link");symlinkSync(auditDir,symbolic);
  await assert.rejects(()=>runSyntheticRehearsal(
   ["rehearse",tenant,dbFile,symbolic,actor,"ci.restore.rehearsal"],env),/directory/);
  chmodSync(auditDir,0o755);
  await assert.rejects(()=>runSyntheticRehearsal(args,env),/directory/);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
