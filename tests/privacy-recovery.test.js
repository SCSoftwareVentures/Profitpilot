import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync} from "node:crypto";
import {canonicalInventory,signPrivacyRecovery,verifyPrivacyRecovery,privacyRecoveryDigest} from "../scripts/privacy-recovery.js";
const {privateKey,publicKey}=generateKeyPairSync("ed25519");
const backupSha256="a".repeat(64);
const row={tenant_id:"33333333-3333-4333-8333-333333333333",batch_id:"44444444-4444-4444-8444-444444444444",file_sha256:"b".repeat(64),authority_ref:"APPROVAL_CI",disposed_at:"2026-01-01T01:02:03.123456Z"};
const inventory={disposals:[row],expiries:[],holds:[]};
const binding=doc=>({backupSha256,expectedManifestSha256:privacyRecoveryDigest(doc)});
test("privacy recovery package binds exact receipts and archive to independent approval",()=>{
 const doc=signPrivacyRecovery(inventory,backupSha256,privateKey);
 assert.deepEqual(verifyPrivacyRecovery(doc,publicKey,binding(doc)).inventory,inventory);
 const wrong={...doc,payload:{...doc.payload,inventory:{...inventory,disposals:[]}}};
 assert.throws(()=>verifyPrivacyRecovery(wrong,publicKey,binding(doc)),/approved digest/);
 assert.throws(()=>verifyPrivacyRecovery(wrong,publicKey,binding(wrong)),/signature/);
 assert.throws(()=>verifyPrivacyRecovery(doc,publicKey,{...binding(doc),backupSha256:"c".repeat(64)}),/backup binding/);
 assert.throws(()=>verifyPrivacyRecovery(doc,generateKeyPairSync("ed25519").publicKey,binding(doc)),/signature/);
 assert.throws(()=>verifyPrivacyRecovery(doc,publicKey,{backupSha256}),/approved digest/);
 const alternate=signPrivacyRecovery({disposals:[],expiries:[],holds:[]},backupSha256,privateKey);
 assert.throws(()=>verifyPrivacyRecovery(alternate,publicKey,binding(doc)),/approved digest/);
});
test("privacy recovery rejects duplicates, unknown fields, conflicting receipts and invalid timestamps",()=>{
 for(const changed of [
  {...inventory,disposals:[row,row]},
  {...inventory,disposals:[row,{...row,batch_id:"55555555-5555-4555-8555-555555555555"}]},
  {...inventory,holds:[{tenant_id:row.tenant_id,batch_id:row.batch_id}]},
  {...inventory,disposals:[{...row,rawData:"secret"}]},
  {...inventory,disposals:[{...row,disposed_at:"2026-02-30T01:02:03.123456Z"}]},
  {...inventory,disposals:[{...row,authority_ref:"invalid free text"}]},
  {...inventory,unexpected:[]}
 ])assert.throws(()=>canonicalInventory(changed));
 assert.throws(()=>signPrivacyRecovery({...inventory,disposals:[{...row,disposed_at:"2099-01-01T00:00:00.000000Z"}]},backupSha256,privateKey),/postdates/);
});
