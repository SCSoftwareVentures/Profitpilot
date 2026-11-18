import test from "node:test";
import assert from "node:assert/strict";
import {createHmac,randomBytes,generateKeyPairSync} from "node:crypto";
import {readPrivacyInventory,signPrivacyRecovery,privacyRecoveryDigest,replayPrivacyRecovery} from "../scripts/privacy-recovery.js";
import pg from "pg";

const enabled=Boolean(process.env.TEST_RESTORE_ADMIN_DATABASE_URL);
test("synthetic logical backup restores all source rows and preserves tenant boundaries",{skip:!enabled,timeout:40000},async()=>{
 const source=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:2});
 const restored=new pg.Pool({connectionString:process.env.TEST_RESTORE_ADMIN_DATABASE_URL,max:2});
 const runtime=new pg.Pool({connectionString:process.env.TEST_RESTORE_APP_DATABASE_URL,max:2});
 const list=`SELECT n.nspname AS schema,c.relname AS name FROM pg_class c
 JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN ('public','private') AND c.relkind IN ('r','p')
 ORDER BY n.nspname,c.relname`;
 const quote=x=>'"'+x.replaceAll('"','""')+'"';
 try{
  const tables=(await source.query(list)).rows;
  assert.ok(tables.length>=20,"restore audit requires populated application schema");
  assert.deepEqual((await restored.query(list)).rows,tables);
  // Compare counts and deterministic row-multiset fingerprints, including
  // private key records, without logging row data or fingerprint values.
  for(const table of tables){
   const name=quote(table.schema)+"."+quote(table.name);
   const query=`SELECT count(*)::text AS n,md5(coalesce(string_agg(h,',' ORDER BY h),'')) AS fingerprint FROM (SELECT md5(to_jsonb(t)::text) AS h FROM ${name} t) fingerprints`;
   const a=(await source.query(query)).rows[0],b=(await restored.query(query)).rows[0];
   assert.ok(a.n===b.n&&a.fingerprint===b.fingerprint,"restored content mismatch: "+name);
  }
  assert.equal((await runtime.query("SELECT id FROM public.contracts")).rowCount,0,"unsigned connections must not enumerate restored contracts");
  await assert.rejects(()=>runtime.query("SELECT secret FROM private.tenant_context_keys"),/permission denied/i);
  const tenant="33333333-3333-4333-8333-333333333333",subject="isolation-tenant-c";
  const result=await restored.query("SELECT key_id,secret FROM private.tenant_context_keys WHERE active ORDER BY key_id LIMIT 1");
  assert.equal(result.rowCount,1,"restored database must have active tenant context key");
  const {key_id:keyId,secret}=result.rows[0];
  const expires=String(Math.floor(Date.now()/1000)+30),nonce=randomBytes(16).toString("hex");
  const signature=createHmac("sha256",secret).update([tenant,subject,expires,nonce,keyId].join("\n")).digest("hex");
  const client=await runtime.connect();
  try{
   await client.query("BEGIN");
   await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[tenant,subject,expires,nonce,keyId,signature]);
   const own=await client.query("SELECT tenant_id FROM public.contracts");
   assert.ok(own.rowCount>0,"valid signed identity must retain access after restoration");
   assert.ok(own.rows.every(x=>x.tenant_id===tenant),"restored signed context must isolate tenants");
   await assert.rejects(()=>client.query("DELETE FROM public.audit_events"),/permission denied/i);
  }finally{try{await client.query("ROLLBACK");}finally{client.release();}}
  assert.equal((await runtime.query("SELECT id FROM public.contracts")).rowCount,0,"restored pooled connection must clear signed context");
  for(const id of [tenant,"44444444-4444-4444-8444-444444444444"]){
   assert.equal((await restored.query("SELECT private.verify_audit_chain($1) AS ok",[id])).rows[0].ok,true,"restored audit chain integrity");
  }
  // A session revoked on the source after the snapshot must remain revoked after replay.
  const uid=(await source.query("SELECT id FROM public.users WHERE auth_subject=$1",[subject])).rows[0].id;
  const authTime=String(Math.floor(Date.now()/1000)-10);
  const issuedAt=String(Math.floor(Date.now()/1000));
  const sessionHash=randomBytes(32).toString("hex");
  const sessionArgs=[subject,authTime,issuedAt,sessionHash,expires,nonce,keyId];
  const sessionSig=createHmac("sha256",secret).update(["profitpilot-session-v1",...sessionArgs].join("\n")).digest("hex");
  const isSessionActive=async()=>(await runtime.query("SELECT private.session_authorized($1,$2,$3,$4,$5,$6,$7,$8) AS allowed",[...sessionArgs,sessionSig])).rows[0].allowed;
  assert.equal(await isSessionActive(),true);
  await source.query("SELECT private.revoke_identity_access($1,'revoke_session','CI_POST_SNAPSHOT',$2)",[uid,sessionHash]);
  const revoked=(await source.query("SELECT session_digest FROM private.revoked_identity_sessions WHERE user_id=$1 AND session_digest=$2",[uid,sessionHash])).rows[0];
  await restored.query("SELECT private.replay_identity_revocation($1,$2,NULL,$3,false,'CI_RECOVERY')",[uid,subject,revoked.session_digest]);
  assert.equal(await isSessionActive(),false);
  // Snapshot predates ciphertext expiry. Reconcile authoritative receipts before service recovery.
  const expiryBatch="de2537ce-957d-478d-98bf-57c6ea37cd3c";
  assert.equal((await restored.query("SELECT scan_state FROM private.quarantined_files WHERE tenant_id=$1 AND batch_id=$2",[tenant,expiryBatch])).rows[0].scan_state,"pending");
  await source.query("SELECT private.expire_quarantine_bytes()");
  const receipt=(await source.query("SELECT file_sha256,disposed_at::text AS disposed_at FROM private.quarantine_expiry_receipts WHERE tenant_id=$1 AND batch_id=$2",[tenant,expiryBatch])).rows[0];
  assert.ok(receipt,"authoritative source expiry receipt required");
  await assert.rejects(()=>restored.query("SELECT private.replay_quarantine_expiry($1,$2,$3,$4)",[tenant,expiryBatch,"0".repeat(64),receipt.disposed_at]),/does not match/);
  await restored.query("SELECT private.set_import_disposal_hold($1,$2,true,'CI_EXPIRY_HOLD')",[tenant,expiryBatch]);
  await assert.rejects(()=>restored.query("SELECT private.replay_quarantine_expiry($1,$2,$3,$4)",[tenant,expiryBatch,receipt.file_sha256,receipt.disposed_at]),/Active legal hold/);
  await restored.query("SELECT private.set_import_disposal_hold($1,$2,false,'CI_EXPIRY_RELEASE')",[tenant,expiryBatch]);
  // Snapshot predates disposal: authoritative source ledger is consulted after restore.
  const batch="f831ab34-efb8-48b4-9979-434711943ea2";
  assert.equal((await restored.query("SELECT id FROM public.import_batches WHERE tenant_id=$1 AND id=$2",[tenant,batch])).rowCount,1);
  assert.equal((await source.query("SELECT private.execute_import_disposal($1,$2) AS removed",[tenant,batch])).rows[0].removed,1);
  const tombstone=(await source.query("SELECT file_sha256,authority_ref,disposed_at::text AS disposed_at FROM private.import_disposal_tombstones WHERE tenant_id=$1 AND batch_id=$2",[tenant,batch])).rows[0];
  const args=[tenant,batch,tombstone.file_sha256,tombstone.authority_ref,tombstone.disposed_at];
  await assert.rejects(()=>restored.query("SELECT private.replay_import_disposal($1,$2,$3,$4,$5)",[tenant,batch,"0".repeat(64),tombstone.authority_ref,tombstone.disposed_at]),/does not match/);
  // Authoritative hold issued after the snapshot, alongside two deletion receipts.
  const held=(await source.query("SELECT b.id FROM public.import_batches b WHERE b.tenant_id=$1 AND b.id NOT IN ($2,$3) AND NOT EXISTS(SELECT 1 FROM private.import_disposal_controls h WHERE h.tenant_id=b.tenant_id AND h.batch_id=b.id AND h.hold_active) ORDER BY b.id LIMIT 1",[tenant,batch,expiryBatch])).rows[0].id;
  await source.query("SELECT private.set_import_disposal_hold($1,$2,true,'CI_NEW_HOLD')",[tenant,held]);
  const reader=await source.connect();
  let inventory;
  try{
   await reader.query("SET ROLE profitpilot_recovery_reader");
   inventory=await readPrivacyInventory(reader);
   await assert.rejects(()=>reader.query("SELECT * FROM private.import_disposal_tombstones"),/permission denied/i);
   await assert.rejects(()=>reader.query("SELECT * FROM public.raw_import_rows"),/permission denied/i);
   await assert.rejects(()=>reader.query("SELECT private.set_import_disposal_hold($1,$2,false,'CI_BAD')",[tenant,held]),/permission denied/i);
  }finally{await reader.query("RESET ROLE");reader.release();}
  await assert.rejects(()=>runtime.query("SELECT private.privacy_recovery_inventory()"),/permission denied/i);
  const {privateKey,publicKey}=generateKeyPairSync("ed25519");
  const backupSha256=process.env.TEST_RESTORE_BACKUP_SHA256;
  const bind=doc=>({backupSha256,expectedManifestSha256:privacyRecoveryDigest(doc)});
  const packageDoc=signPrivacyRecovery(inventory,backupSha256,privateKey);
  const incorrect=signPrivacyRecovery({...inventory,disposals:inventory.disposals.map(d=>d.batch_id===batch?{...d,file_sha256:"0".repeat(64)}:d)},backupSha256,privateKey);
  await assert.rejects(()=>replayPrivacyRecovery(restored,incorrect,publicKey,bind(incorrect)),/does not match/);
  assert.equal((await restored.query("SELECT count(*)::int AS n FROM private.import_disposal_controls WHERE tenant_id=$1 AND batch_id=$2 AND hold_active",[tenant,held])).rows[0].n,0,"a failed package rolls back new holds");
  assert.equal((await restored.query("SELECT scan_state FROM private.quarantined_files WHERE batch_id=$1",[expiryBatch])).rows[0].scan_state,"pending");
  assert.deepEqual(await replayPrivacyRecovery(restored,packageDoc,publicKey,bind(packageDoc)),{holds:1,disposals:1,expiries:1});
  assert.deepEqual(await replayPrivacyRecovery(restored,packageDoc,publicKey,bind(packageDoc)),{holds:0,disposals:0,expiries:0});
  assert.deepEqual(await readPrivacyInventory(restored),inventory);
  assert.equal((await restored.query("SELECT hold_active FROM private.import_disposal_controls WHERE tenant_id=$1 AND batch_id=$2",[tenant,held])).rows[0].hold_active,true);
  await assert.rejects(()=>restored.query("DELETE FROM private.import_disposal_tombstones WHERE batch_id=$1",[batch]),/append-only/i);
  await assert.rejects(()=>restored.query("UPDATE private.import_disposal_events SET authority_ref='CI_TAMPER' WHERE batch_id=$1",[batch]),/append-only/i);
  const replayArgs=[tenant,expiryBatch,receipt.file_sha256,receipt.disposed_at];
  assert.equal((await restored.query("SELECT private.replay_quarantine_expiry($1,$2,$3,$4) AS changed",replayArgs)).rows[0].changed,false);
  assert.deepEqual((await restored.query("SELECT scan_state,ciphertext FROM private.quarantined_files WHERE tenant_id=$1 AND batch_id=$2",[tenant,expiryBatch])).rows[0],{scan_state:"disposed",ciphertext:null});
  await assert.rejects(()=>restored.query("UPDATE private.quarantined_files SET scan_state='pending',ciphertext=decode('aa','hex'),disposed_at=NULL WHERE tenant_id=$1 AND batch_id=$2",[tenant,expiryBatch]),/immutable|check constraint/);
  await assert.rejects(()=>restored.query("DELETE FROM private.quarantine_expiry_receipts WHERE tenant_id=$1 AND batch_id=$2",[tenant,expiryBatch]),/append-only/i);
  assert.equal((await restored.query("SELECT id FROM public.import_batches WHERE tenant_id=$1 AND id=$2",[tenant,expiryBatch])).rowCount,1);
  assert.equal((await restored.query("SELECT private.replay_import_disposal($1,$2,$3,$4,$5) AS removed",args)).rows[0].removed,0);
  assert.equal((await restored.query("SELECT id FROM public.import_batches WHERE tenant_id=$1 AND id=$2",[tenant,batch])).rowCount,0);
  assert.equal((await restored.query("SELECT id FROM public.raw_import_rows WHERE tenant_id=$1 AND batch_id=$2",[tenant,batch])).rowCount,0);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.import_disposal_tombstones"),/permission denied/i);
 }finally{await Promise.all([source.end(),restored.end(),runtime.end()]);}
});
