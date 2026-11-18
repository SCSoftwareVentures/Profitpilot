import test from "node:test";
import assert from "node:assert/strict";
import {createHmac,randomBytes,generateKeyPairSync} from "node:crypto";
import {readPrivacyInventory,signPrivacyRecovery,privacyRecoveryDigest,replayPrivacyRecovery} from "../scripts/privacy-recovery.js";
import pg from "pg";
import {readSecurityInventory,signSecurityRecovery,replaySecurityRecovery,securityRecoveryDigest} from "../scripts/security-recovery.js";
import {randomUUID} from "node:crypto";

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
  // Verify a confirmed payroll record was actually present in the encrypted
  // snapshot, not just an empty new table. Never print receipt or session data.
  const payroll = (await restored.query(`SELECT c.tenant_id,c.allocation_run_id,pp.id AS pool_id
   FROM private.payroll_confirmation_receipts c
   JOIN public.tenants t ON t.id=c.tenant_id
   JOIN public.allocation_runs r ON r.tenant_id=c.tenant_id AND r.id=c.allocation_run_id
   JOIN public.payroll_pools pp ON pp.tenant_id=r.tenant_id AND pp.id=r.payroll_pool_id
   JOIN private.payroll_proposal_decisions d ON d.tenant_id=c.tenant_id AND d.proposal_id=c.proposal_id
   WHERE t.legal_name='Synthetic payroll review' AND r.status='confirmed'
   AND r.reviewer_id=c.reviewer_id AND d.decision='reviewed' AND d.reviewer_id=c.reviewer_id`)).rows;
  assert.equal(payroll.length,1,"confirmed payroll fixture must survive the actual encrypted restore");
  const restoredPayroll=payroll[0];
  assert.equal((await restored.query("SELECT private.verify_audit_chain($1) AS ok",[restoredPayroll.tenant_id])).rows[0].ok,true);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.payroll_confirmation_receipts"),/permission denied/i);
  await assert.rejects(()=>restored.query("DELETE FROM private.payroll_confirmation_receipts WHERE tenant_id=$1 AND allocation_run_id=$2",[restoredPayroll.tenant_id,restoredPayroll.allocation_run_id]),e=>e.code==="55000");
  await assert.rejects(()=>restored.query("UPDATE public.payroll_pools SET source_ref='restore-probe' WHERE tenant_id=$1 AND id=$2",[restoredPayroll.tenant_id,restoredPayroll.pool_id]),e=>e.code==="55000");
  console.log("Confirmed payroll receipt, chained audit and immutable evidence verified in isolated encrypted restore");
  const retained=(await restored.query(`SELECT p.tenant_id,p.allocation_run_id,p.order_id,o.requested_by,d.decided_by,c.consumed_by
   FROM private.financial_backup_plans p JOIN public.tenants t ON t.id=p.tenant_id
   JOIN private.security_work_orders o ON o.tenant_id=p.tenant_id AND o.id=p.order_id
   JOIN private.security_work_decisions d ON d.tenant_id=p.tenant_id AND d.order_id=p.order_id AND d.decision='approved'
   JOIN private.security_work_consumptions c ON c.tenant_id=p.tenant_id AND c.order_id=p.order_id
   WHERE t.legal_name='Synthetic payroll supersession'`)).rows;
  assert.equal(retained.length,1,"populated dual-approved backup plan must survive encrypted restore");
  const retainedPlan=retained[0];
  assert.notEqual(retainedPlan.requested_by,retainedPlan.decided_by);
  assert.equal(retainedPlan.requested_by,retainedPlan.consumed_by);
  const retainedArgs=[retainedPlan.tenant_id,retainedPlan.allocation_run_id];
  const retainedStatus=(await restored.query("SELECT private.financial_retention_dependency_status($1,$2) AS s",retainedArgs)).rows[0].s;
  assert.equal(retainedStatus.retention,"hold-recorded");
  assert.equal(retainedStatus.correctionLineage,true);assert.equal(retainedStatus.overlappingCalculations,true);
  assert.equal(retainedStatus.batchHold,true);assert.equal(retainedStatus.backupPlan,"recorded-unverified");
  assert.equal(retainedStatus.authorizesDisposal,false);
  assert.equal((await restored.query("SELECT private.verify_audit_chain($1) AS ok",[retainedPlan.tenant_id])).rows[0].ok,true);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.financial_backup_plans"),/permission denied/i);
  await assert.rejects(()=>restored.query("DELETE FROM private.financial_backup_plans WHERE tenant_id=$1 AND order_id=$2",[retainedPlan.tenant_id,retainedPlan.order_id]),e=>e.code==="55000");
  await assert.rejects(()=>restored.query("DELETE FROM private.financial_retention_holds WHERE tenant_id=$1 AND allocation_run_id=$2",retainedArgs),e=>e.code==="55000");
  assert.equal((await runtime.query("SELECT id FROM public.contracts")).rowCount,0,"unsigned connections must not enumerate restored contracts");
  await assert.rejects(()=>runtime.query("SELECT secret FROM private.tenant_context_keys"),/permission denied/i);
  const delivery=(await restored.query("SELECT d.tenant_id,d.case_id,d.order_id FROM private.privacy_delivery_authorizations d JOIN public.tenants t ON t.id=d.tenant_id WHERE t.legal_name='Synthetic assisted privacy delivery'")).rows;
  assert.equal(delivery.length,1,"populated assisted release authority must survive encrypted restore");
  assert.equal((await restored.query("SELECT private.verify_audit_chain($1) AS ok",[delivery[0].tenant_id])).rows[0].ok,true);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.privacy_delivery_authorizations"),/permission denied/i);
  await assert.rejects(()=>restored.query("DELETE FROM private.privacy_delivery_authorizations WHERE tenant_id=$1 AND order_id=$2",[delivery[0].tenant_id,delivery[0].order_id]),e=>e.code==="55000");
  console.log("Assisted privacy release authorization and immutable audit restored");
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
  const incident=randomUUID(),otherTenant="44444444-4444-4444-8444-444444444444";
  await source.query("SELECT private.activate_tenant_emergency($1,$2,'suspected_compromise','CI_POST_SNAPSHOT')",[otherTenant,incident]);
  const securityReader=await source.connect();let secInventory;
  try{await securityReader.query("SET ROLE profitpilot_recovery_reader");secInventory=await readSecurityInventory(securityReader);await assert.rejects(()=>securityReader.query("SELECT * FROM public.users"),/permission denied/i);}
  finally{await securityReader.query("RESET ROLE");securityReader.release();}
  await assert.rejects(()=>runtime.query("SELECT private.security_recovery_inventory()"),/permission denied/i);
  // A drifted authoritative catalogue must refuse both recovery inventories.
  const drift=await source.connect();
  try{
   await drift.query("BEGIN");
   await drift.query("GRANT UPDATE(decision) ON public.mapping_decisions TO profitpilot_app");
   await drift.query("SET LOCAL ROLE profitpilot_recovery_reader");
   for(const fn of ["security_recovery_inventory","privacy_recovery_inventory"]){
    await drift.query("SAVEPOINT probe");
    await assert.rejects(()=>drift.query("SELECT private."+fn+"()"),e=>e.code==="55000");
    await drift.query("ROLLBACK TO SAVEPOINT probe");
   }
  }finally{await drift.query("ROLLBACK");drift.release();}
  const keys=generateKeyPairSync("ed25519"),archive=process.env.TEST_RESTORE_BACKUP_SHA256;
  const securityDoc=signSecurityRecovery(secInventory,archive,keys.privateKey);
  const securityBinding={backupSha256:archive,expectedManifestSha256:securityRecoveryDigest(securityDoc)};
  await assert.rejects(()=>replaySecurityRecovery(restored,securityDoc,keys.publicKey,{...securityBinding,expectedManifestSha256:"0".repeat(64)}),/binding/);
  assert.equal(await isSessionActive(),true);
  // Post-snapshot case history or an account correction cannot be silently lost.
  const sensitiveSource=await source.connect();
  try{
   await sensitiveSource.query("BEGIN");
   await sensitiveSource.query("INSERT INTO private.privacy_rights_cases(tenant_id,id,kind,channel,opened_by) VALUES($1,$2,'access','self',$3)",[tenant,randomUUID(),uid]);
   const updated=await readSecurityInventory(sensitiveSource);
   assert.notEqual(updated.sensitive[0].digest,secInventory.sensitive[0].digest);
   const newer=signSecurityRecovery(updated,archive,keys.privateKey);
   await assert.rejects(()=>replaySecurityRecovery(restored,newer,keys.publicKey,{backupSha256:archive,expectedManifestSha256:securityRecoveryDigest(newer)}),/isolated/);
   assert.equal(await isSessionActive(),true);
   await sensitiveSource.query("ROLLBACK");
   await sensitiveSource.query("BEGIN");
   await sensitiveSource.query("UPDATE public.users SET email='corrected@example.invalid' WHERE id=$1",[uid]);
   const changedEmail=await readSecurityInventory(sensitiveSource);
   assert.notEqual(changedEmail.sensitive[0].digest,secInventory.sensitive[0].digest);
   const emailDoc=signSecurityRecovery(changedEmail,archive,keys.privateKey);
   await assert.rejects(()=>replaySecurityRecovery(restored,emailDoc,keys.publicKey,{backupSha256:archive,expectedManifestSha256:securityRecoveryDigest(emailDoc)}),/isolated/);
  }finally{await sensitiveSource.query("ROLLBACK");sensitiveSource.release();}
  // Isolate a restore when post-snapshot financial protection differs.
  // The trusted admin simulates new authoritative records, not actual legal evidence.
  const financialSource=await source.connect();
  try{
   await financialSource.query("BEGIN");
   await financialSource.query("INSERT INTO private.financial_retention_holds(tenant_id,allocation_run_id,hold_id,evidence_digest) VALUES($1,$2,$3,$4)",[...retainedArgs,randomUUID(),"a".repeat(64)]);
   const holdInventory=await readSecurityInventory(financialSource);
   assert.notEqual(holdInventory.sensitive[0].digest,secInventory.sensitive[0].digest);
   const holdDoc=signSecurityRecovery(holdInventory,archive,keys.privateKey);
   await assert.rejects(()=>replaySecurityRecovery(restored,holdDoc,keys.publicKey,{backupSha256:archive,expectedManifestSha256:securityRecoveryDigest(holdDoc)}),/isolated/);
   await financialSource.query("ROLLBACK");
   await financialSource.query("BEGIN");
   // The existing order and decision are left unchanged; a separate plan is
   // inserted under the trusted administrator boundary using an existing
   // consumed correction order solely to isolate the plan fingerprint check.
   const newOrder=(await financialSource.query("SELECT order_id FROM private.payroll_supersessions WHERE tenant_id=$1 AND old_run_id=$2",retainedArgs)).rows[0].order_id;
   await financialSource.query("INSERT INTO private.financial_backup_plans(tenant_id,allocation_run_id,order_id,inventory_digest,disposition_digest,checked_on) VALUES($1,$2,$3,$4,$5,(clock_timestamp() AT TIME ZONE 'UTC')::date)",[...retainedArgs,newOrder,"c".repeat(64),"d".repeat(64)]);
   const planInventory=await readSecurityInventory(financialSource);
   assert.notEqual(planInventory.sensitive[0].digest,secInventory.sensitive[0].digest);
   const planDoc=signSecurityRecovery(planInventory,archive,keys.privateKey);
   await assert.rejects(()=>replaySecurityRecovery(restored,planDoc,keys.publicKey,{backupSha256:archive,expectedManifestSha256:securityRecoveryDigest(planDoc)}),/isolated/);
   assert.equal(await isSessionActive(),true);
  }finally{await financialSource.query("ROLLBACK");financialSource.release();}
  console.log("Populated retention and backup records restored; newer signed hold and plan inventories deny older snapshots");
  const applied=await replaySecurityRecovery(restored,securityDoc,keys.publicKey,securityBinding);
  assert.equal(applied.sessions,1);assert.equal(applied.incidents,1);
  assert.ok(Object.values(await replaySecurityRecovery(restored,securityDoc,keys.publicKey,securityBinding)).every(n=>n===0));
  assert.equal((await restored.query("SELECT count(*)::int AS n FROM private.tenant_emergency_incidents WHERE incident_id=$1 AND released_at IS NULL",[incident])).rows[0].n,1);
  assert.equal((await restored.query("SELECT private.verify_audit_chain($1) AS ok",[otherTenant])).rows[0].ok,true);
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
