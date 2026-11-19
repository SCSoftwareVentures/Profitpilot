import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import pg from "pg";
import {rotateTenantKey} from "../scripts/rotate-tenant-key.js";

test("invalid key operations are rejected before database access",async()=>{
 for(const args of [{action:"stage",keyId:"bad key",secret:"a".repeat(64)},{action:"stage",keyId:"valid",secret:"a"},{action:"revoke",keyId:"same",replacementId:"same",secret:"a".repeat(64)},{action:"delete",keyId:"valid",secret:"a".repeat(64)}]){
  await assert.rejects(()=>rotateTenantKey({connect(){throw new Error("unexpected connection");}},args),e=>e.message!=="unexpected connection");
 }
});
test("database key rotation is audited, immutable and inaccessible to runtime",{skip:!process.env.TEST_APP_DATABASE_URL},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const runtime=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL});
 const id="ci-"+randomBytes(8).toString("hex"),replacementId=id+"-next";
 const secret=randomBytes(32).toString("hex"),nextSecret=randomBytes(32).toString("hex");
 try{
  await rotateTenantKey(admin,{action:"stage",keyId:id,secret});
  await assert.rejects(()=>rotateTenantKey(admin,{action:"stage",keyId:id,secret:nextSecret}),/already been used/);
  await assert.rejects(()=>rotateTenantKey(admin,{action:"stage",keyId:replacementId,secret}),/already been used/);
  await rotateTenantKey(admin,{action:"stage",keyId:replacementId,secret:nextSecret});
  await assert.rejects(()=>rotateTenantKey(admin,{action:"revoke",keyId:id,replacementId,secret}),/replacement key could not be verified/);
  await rotateTenantKey(admin,{action:"revoke",keyId:id,replacementId,secret:nextSecret});
  assert.deepEqual((await admin.query("SELECT event_type FROM private.tenant_key_rotation_events WHERE key_id=$1 ORDER BY id",[id])).rows.map(x=>x.event_type),["staged","revoked"]);
  await assert.rejects(()=>admin.query("UPDATE private.tenant_context_keys SET active=true WHERE key_id=$1",[id]),/immutable/);
  await assert.rejects(()=>admin.query("UPDATE private.tenant_context_keys SET secret=decode($2,'hex') WHERE key_id=$1",[replacementId,secret]),/immutable/);
  await assert.rejects(()=>admin.query("DELETE FROM private.tenant_context_keys WHERE key_id=$1",[id]),/cannot be deleted/);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.tenant_key_rotation_events"),/permission denied/);
  await assert.rejects(()=>rotateTenantKey(runtime,{action:"stage",keyId:"runtime-denied",secret}),/permission denied/);
 }finally{await Promise.all([admin.end(),runtime.end()]);}
});
