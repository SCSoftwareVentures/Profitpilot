import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync} from "node:crypto";
import {canonicalSecurityInventory,recoveryPlan,signSecurityRecovery,verifySecurityRecovery,securityRecoveryDigest} from "../scripts/security-recovery.js";
const tenant="11111111-1111-4111-8111-111111111111",user="22222222-2222-4222-8222-222222222222",incident="33333333-3333-4333-8333-333333333333";
const baseline={tenants:[{id:tenant,status:"active"}],users:[{id:user,status:"active",subject_hash:"a".repeat(64)}],memberships:[{tenant_id:tenant,user_id:user,role:"read_only",status:"active"}],cutoffs:[],sessions:[],keys:[{key_id:"primary",active:true}],incidents:[],sensitive:[{digest:"e".repeat(64)}]};
const next={...baseline,users:[{...baseline.users[0],status:"disabled"}],memberships:[{...baseline.memberships[0],status:"revoked"}],cutoffs:[{user_id:user,revoked_through:"100"}],sessions:[{user_id:user,session_digest:"b".repeat(64)}],keys:[{key_id:"primary",active:false}],incidents:[{incident_id:incident,tenant_id:tenant,category:"suspected_compromise",released:false}]};
const {privateKey,publicKey}=generateKeyPairSync("ed25519"),backup="c".repeat(64);
const bind=doc=>({backupSha256:backup,expectedManifestSha256:securityRecoveryDigest(doc)});
test("security recovery binds exact canonical inventory and independently approved archive",()=>{
 assert.throws(()=>signSecurityRecovery(next,backup,privateKey,"1970-01-01T00:00:01.000Z"),/postdates/);
 const doc=signSecurityRecovery(next,backup,privateKey);
 assert.deepEqual(verifySecurityRecovery(doc,publicKey,bind(doc)),canonicalSecurityInventory(next));
 const forged={...doc,payload:{...doc.payload,inventory:baseline}};
 assert.throws(()=>verifySecurityRecovery(forged,publicKey,bind(doc)),/binding/);
 assert.throws(()=>verifySecurityRecovery(forged,publicKey,bind(forged)),/signature/);
 assert.throws(()=>verifySecurityRecovery(doc,publicKey,{...bind(doc),backupSha256:"d".repeat(64)}),/binding/);
});
test("deny-only reconciliation cannot re-enable membership, user, keys, or close incidents",()=>{
 const p=recoveryPlan(baseline,next);
 for(const k of ["users","memberships","cutoffs","sessions","keys","incidents"])assert.equal(p[k].length,1,k);
 assert.ok(Object.values(recoveryPlan(next,next)).every(x=>x.length===0));
 assert.throws(()=>recoveryPlan(next,baseline),/isolated/);
 assert.throws(()=>recoveryPlan(baseline,{...baseline,memberships:[{...baseline.memberships[0],role:"owner"}]}),/isolated/);
 assert.throws(()=>recoveryPlan(next,{...next,incidents:[{...next.incidents[0],released:true}]}),/isolated/);
 assert.throws(()=>canonicalSecurityInventory({...next,users:[{...next.users[0],email:"not allowed"}]}));
 assert.throws(()=>canonicalSecurityInventory({...next,sessions:[...next.sessions,...next.sessions]}));
 assert.throws(()=>canonicalSecurityInventory({...next,users:[]}));
 assert.ok(Object.values(recoveryPlan({...next,cutoffs:[{user_id:user,revoked_through:"101"}]},next)).every(x=>x.length===0));
});

test("sensitive recovery fingerprint mismatch requires isolation of old snapshot",()=>{
 const changed={...baseline,sensitive:[{digest:"f".repeat(64)}]};
 assert.throws(()=>recoveryPlan(baseline,changed),/isolated/);
 assert.throws(()=>recoveryPlan(changed,baseline),/isolated/);
 assert.throws(()=>canonicalSecurityInventory({...baseline,sensitive:[]}));
 assert.throws(()=>canonicalSecurityInventory({...baseline,sensitive:[{digest:"0".repeat(64)}]}));
 assert.throws(()=>canonicalSecurityInventory({...baseline,sensitive:[...baseline.sensitive,...baseline.sensitive]}));
});
