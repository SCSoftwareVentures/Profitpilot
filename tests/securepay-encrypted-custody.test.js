import test from "node:test";
import assert from "node:assert/strict";
import {createHash,randomBytes,randomUUID} from "node:crypto";
import {custodyKeySettings,custodyAad,sealCustodyBytes,decryptCustodyBytes,verifyScanMac} from "../src/securepay-encrypted-custody.js";
const bytes=Buffer.from("SecurePay S10 synthetic custody contents.\n");
const hash=createHash("sha256").update(bytes).digest("hex");
const scope={tenantId:randomUUID(),caseId:randomUUID(),evidenceId:randomUUID(),
 clientRequestId:randomUUID(),actorId:randomUUID(),sha256:hash,byteCount:bytes.length,
 mediaType:"text/plain",keyId:"s10-demo-key-v1"};
const key1=randomBytes(32).toString("hex"),key2=randomBytes(32).toString("hex");
const env={SECUREPAY_CUSTODY_ENCRYPTION_KEY:key1,SECUREPAY_CUSTODY_ATTESTATION_KEY:key2,
 SECUREPAY_CUSTODY_KEY_ID:scope.keyId};
test("S10 no insecure default keys or reuse of signing/encryption key",()=>{
 assert.throws(()=>custodyKeySettings({}),/required/);
 assert.throws(()=>custodyKeySettings({...env,SECUREPAY_CUSTODY_ATTESTATION_KEY:key1}),/required/);
 assert.throws(()=>custodyKeySettings({...env,SECUREPAY_CUSTODY_KEY_ID:"../secret"}),/required/);
 assert.throws(()=>custodyKeySettings({...env,SECUREPAY_CUSTODY_ENCRYPTION_KEY:"a".repeat(40)}),/required/);
});
test("S10 AES-GCM binds exact scope and rejects tampered ciphertext, tag, and AAD",()=>{
 const keys=custodyKeySettings(env);
 const sealed=sealCustodyBytes(bytes,scope,keys);
 assert.equal(sealed.algorithm,"aes-256-gcm");
 assert.equal(sealed.nonce.length,12);assert.equal(sealed.tag.length,16);
 assert.notDeepEqual(sealed.ciphertext,bytes);
 assert.deepEqual(decryptCustodyBytes(sealed,scope,keys),bytes);
 const wrong={...scope,caseId:randomUUID()};
 assert.throws(()=>decryptCustodyBytes(sealed,wrong,keys),/AAD/);
 const swapped={...sealed,tag:Buffer.from(sealed.tag)};
 swapped.tag[0]^=1;assert.throws(()=>decryptCustodyBytes(swapped,scope,keys));
 const changed={...sealed,ciphertext:Buffer.from(sealed.ciphertext)};
 changed.ciphertext[1]^=1;assert.throws(()=>decryptCustodyBytes(changed,scope,keys),/checksum/);
 assert.throws(()=>sealCustodyBytes(Buffer.from("changed"),scope,keys));
 assert.notDeepEqual(custodyAad(scope),custodyAad({...scope,tenantId:randomUUID()}));
});
test("S10 operator-recorded scanner MAC is scoped, distinct-key and fail-closed",()=>{
 const keys=custodyKeySettings(env);
 const s=sealCustodyBytes(bytes,scope,keys);
 const row={tenant_id:scope.tenantId,case_id:scope.caseId,evidence_id:scope.evidenceId,
  client_request_id:scope.clientRequestId,received_by:scope.actorId,
  sha256:scope.sha256,byte_count:scope.byteCount,media_type:scope.mediaType,
  key_id:scope.keyId,scan_observed_at:new Date(s.observedAt),
  scanner_attestation_mac:s.attestationMac,ciphertext_sha256:s.ciphertextSha256};
 assert.equal(verifyScanMac(row,keys),true);
 assert.equal(verifyScanMac({...row,sha256:"b".repeat(64)},keys),false);
 assert.equal(verifyScanMac({...row,case_id:randomUUID()},keys),false);
 assert.equal(verifyScanMac({...row,scan_observed_at:new Date(1000)},keys),false);
 assert.equal(verifyScanMac({...row,scanner_attestation_mac:"z"},keys),false);
 assert.equal(verifyScanMac(row,{...keys,keyId:"other-key"}),false);
 assert.equal(verifyScanMac(row,{...keys,macKey:randomBytes(32)}),false);
});
