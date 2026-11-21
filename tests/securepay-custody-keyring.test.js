import test from "node:test";
import assert from "node:assert/strict";
import {createHash,randomBytes,randomUUID} from "node:crypto";
import {mkdtempSync,writeFileSync,rmSync,symlinkSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {custodyKeyringSettings,resolveCustodyReceiptKey,sealCustodyBytes,
 decryptCustodyBytes,verifyScanMac} from "../src/securepay-encrypted-custody.js";

const randomKey=()=>randomBytes(32).toString("hex");
const old={keyId:"key-2026-01",encryptionKey:randomKey(),attestationKey:randomKey(),status:"recovery-only"};
const active={keyId:"key-2026-02",encryptionKey:randomKey(),attestationKey:randomKey(),status:"active"};
const makeManifest=(keys=[old,active],activeKeyId=active.keyId)=>({activeKeyId,keys});
const withManifest=(manifest,callback)=>{
 const dir=mkdtempSync(join(tmpdir(),"securepay-keyring-"));
 const file=join(dir,"keys.json");
 try{
  writeFileSync(file,typeof manifest==="string"?manifest:JSON.stringify(manifest),{mode:0o600});
  return callback({NODE_ENV:"test",SECUREPAY_CUSTODY_KEYRING_FILE:file},dir);
 }finally{rmSync(dir,{recursive:true,force:true});}
};
const payload=Buffer.from("synthetic retained evidence after key rotation");
const hash=createHash("sha256").update(payload).digest("hex");
const scope=keyId=>({tenantId:randomUUID(),caseId:randomUUID(),evidenceId:randomUUID(),
 clientRequestId:randomUUID(),actorId:randomUUID(),sha256:hash,byteCount:payload.length,
 mediaType:"text/plain",keyId});
const receipt=(s,c)=>({tenant_id:c.tenantId,case_id:c.caseId,evidence_id:c.evidenceId,
 client_request_id:c.clientRequestId,received_by:c.actorId,sha256:c.sha256,
 byte_count:c.byteCount,media_type:c.mediaType,key_id:c.keyId,
 scan_observed_at:new Date(s.observedAt),scanner_attestation_mac:s.attestationMac,
 ciphertext_sha256:s.ciphertextSha256});

test("S11.1 rotation uses new active key while old receipts remain recoverable",()=>{
 withManifest(makeManifest(),env=>{
  const ring=custodyKeyringSettings(env);
  assert.equal(ring.mode,"mounted-keyring");
  assert.equal(ring.active.keyId,active.keyId);
  const contextOld=scope(old.keyId);
  const contextNew=scope(active.keyId);
  const keyOld=resolveCustodyReceiptKey(ring,old.keyId);
  const keyNew=resolveCustodyReceiptKey(ring,active.keyId);
  assert.ok(keyOld);assert.equal(keyNew,ring.active);
  const sealedOld=sealCustodyBytes(payload,contextOld,keyOld);
  const sealedNew=sealCustodyBytes(payload,contextNew,ring.active);
  assert.deepEqual(decryptCustodyBytes(sealedOld,contextOld,keyOld),payload);
  assert.deepEqual(decryptCustodyBytes(sealedNew,contextNew,keyNew),payload);
  assert.equal(verifyScanMac(receipt(sealedOld,contextOld),keyOld),true);
  assert.equal(verifyScanMac(receipt(sealedNew,contextNew),keyNew),true);
  assert.equal(verifyScanMac(receipt(sealedOld,contextOld),keyNew),false);
  assert.throws(()=>decryptCustodyBytes(sealedOld,contextOld,keyNew),/Matching/);
  assert.throws(()=>sealCustodyBytes(payload,contextOld,ring.active),/matching/);
  assert.equal(resolveCustodyReceiptKey(ring,"unknown-key"),null);
 });
});

test("S11.1 missing historical key fails closed rather than silently claiming validity",()=>{
 const past=withManifest(makeManifest(),env=>{
  const ring=custodyKeyringSettings(env),context=scope(old.keyId);
  const sealed=sealCustodyBytes(payload,context,resolveCustodyReceiptKey(ring,old.keyId));
  return {context,sealed};
 });
 withManifest(makeManifest([active]),env=>{
  const ring=custodyKeyringSettings(env);
  assert.equal(resolveCustodyReceiptKey(ring,past.context.keyId),null);
  assert.equal(verifyScanMac(receipt(past.sealed,past.context),resolveCustodyReceiptKey(ring,past.context.keyId)),false);
 });
});

test("S11.1 malformed, duplicate, reused, or ambiguously configured secrets fail closed",()=>{
 const invalid=[
  "not-json",makeManifest([],active.keyId),
  makeManifest([old],active.keyId),
  makeManifest([old,{...active,status:"recovery-only"}]),
  makeManifest([old,{...active,keyId:old.keyId}]),
  makeManifest([{...old,encryptionKey:active.attestationKey},active]),
  makeManifest([old,{...active,attestationKey:active.encryptionKey}]),
  makeManifest([old,{...active,status:"active",extra:"unknown"}]),
  {...makeManifest(),newField:42},
  makeManifest([old,{...active,keyId:"../bad"}])
 ];
 for(const item of invalid)withManifest(item,env=>assert.throws(()=>custodyKeyringSettings(env)));
 withManifest(makeManifest(),env=>{
  assert.throws(()=>custodyKeyringSettings({...env,SECUREPAY_CUSTODY_ENCRYPTION_KEY:"f".repeat(64)}),/ambiguous/);
  assert.throws(()=>custodyKeyringSettings({...env,SECUREPAY_CUSTODY_KEYRING:"{}"}),/ambiguous/);
  const {SECUREPAY_CUSTODY_KEYRING_FILE,...withoutFile}=env;
  assert.throws(()=>custodyKeyringSettings({...withoutFile,SECUREPAY_CUSTODY_KEYRING:"{}"}),/[Mm]ounted/);
 });
});

test("S11.1 mounted keyring inherits no-follow secret file protections",()=>{
 withManifest(makeManifest(),(env,dir)=>{
  const link=join(dir,"keys-link.json");
  symlinkSync(env.SECUREPAY_CUSTODY_KEYRING_FILE,link);
  assert.throws(()=>custodyKeyringSettings({...env,SECUREPAY_CUSTODY_KEYRING_FILE:link}));
 });
});

test("S11.1 S10 explicitly keyed compatibility remains supported",()=>{
 const env={NODE_ENV:"test",SECUREPAY_CUSTODY_ENCRYPTION_KEY:randomKey(),
  SECUREPAY_CUSTODY_ATTESTATION_KEY:randomKey(),SECUREPAY_CUSTODY_KEY_ID:"old-s10-key"};
 const ring=custodyKeyringSettings(env);
 assert.equal(ring.mode,"single-key-compatibility");
 assert.equal(ring.byId.size,1);
 assert.equal(resolveCustodyReceiptKey(ring,"old-s10-key"),ring.active);
 assert.equal(resolveCustodyReceiptKey(ring,"old-s10-key-2"),null);
});
