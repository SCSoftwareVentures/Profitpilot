import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,randomUUID} from "node:crypto";
import pg from "pg";
import {signCheckpoint,verifyCheckpoint,verifyHistoricalCheckpoint} from "../scripts/audit-checkpoint.js";
import {createSecurityAlertPolicy} from "../server/security-alert-policy.js";
const {privateKey,publicKey}=generateKeyPairSync("ed25519");
const entry={tenant_id:"33333333-3333-4333-8333-333333333333",entry_count:"1",head_hash:"a".repeat(64)};

test("audit checkpoints are canonical, signed and reject modifications or wrong keys",()=>{
 const other={...entry,tenant_id:"44444444-4444-4444-8444-444444444444"};
 const doc=signCheckpoint([other,entry],privateKey);
 const payload=verifyCheckpoint(doc,publicKey);
 assert.deepEqual(payload.entries,[entry,other]);
 assert.throws(()=>verifyCheckpoint({...doc,payload:{...payload,entries:[{...entry,head_hash:"b".repeat(64)},other]}},publicKey),/signature/i);
 assert.throws(()=>verifyCheckpoint(doc,generateKeyPairSync("ed25519").publicKey),/signature/i);
 assert.throws(()=>signCheckpoint([entry,entry],privateKey),/Duplicate/);
 assert.throws(()=>signCheckpoint([{...entry,entry_count:"0"}],privateKey));
 assert.throws(()=>signCheckpoint([{...entry,entry_count:"9223372036854775808"}],privateKey));
});
test("historical checkpoint verification rejects missing or rewritten history",async()=>{
 const doc=signCheckpoint([entry],privateKey);
 const good={query:async(sql,args)=>{assert.match(sql,/audit_checkpoint_matches/);assert.deepEqual(args,[entry.tenant_id,entry.entry_count,entry.head_hash]);return {rows:[{ok:true}]};}};
 assert.deepEqual(await verifyHistoricalCheckpoint(good,doc,publicKey),{verified:1});
 await assert.rejects(()=>verifyHistoricalCheckpoint({query:async()=>({rows:[{ok:false}]})},doc,publicKey),/Historical checkpoint mismatch/);
});
test("security alerts require sustained thresholds, suppress duplicates and clear on recovery",()=>{
 const evaluate=createSecurityAlertPolicy();
 const normal={requests:100,authDenied:0,roleDenied:0,rateLimited:0,unavailable:0,serverError:0,slow:0,aborted:0};
 const spike={...normal,authDenied:30,rateLimited:20};
 assert.deepEqual(evaluate(spike),[]);
 assert.deepEqual(evaluate(spike),[
  {event:"api_security_alert",category:"auth_denial_spike",state:"active"},
  {event:"api_security_alert",category:"rate_limit_spike",state:"active"}
 ]);
 assert.deepEqual(evaluate(spike),[]);
 assert.deepEqual(evaluate(normal),[
  {event:"api_security_alert",category:"auth_denial_spike",state:"cleared"},
  {event:"api_security_alert",category:"rate_limit_spike",state:"cleared"}
 ]);
 assert.deepEqual(evaluate(normal),[]);
 assert.deepEqual(evaluate(spike),[]);
});
test("restricted audit reader verifies externally signed historical prefix after new events",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:30000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const app=new pg.Pool({connectionString:process.env.TEST_APP_DATABASE_URL});
 const reader=await admin.connect();
 const tenant=entry.tenant_id;
 try{
  await reader.query("SET ROLE profitpilot_audit_reader");
  await assert.rejects(()=>reader.query("SELECT * FROM public.audit_events"),/permission denied/i);
  await assert.rejects(()=>reader.query("SELECT * FROM private.audit_chain_entries"),/permission denied/i);
  await assert.rejects(()=>app.query("SELECT * FROM private.audit_checkpoint_heads()"),/permission denied/i);
  const rows=(await reader.query("SELECT * FROM private.audit_checkpoint_heads()")).rows;
  assert.ok(rows.some(r=>r.tenant_id===tenant));
  const doc=signCheckpoint(rows,privateKey);
  assert.deepEqual(await verifyHistoricalCheckpoint(reader,doc,publicKey),{verified:rows.length});
  const id=randomUUID();
  await admin.query("INSERT INTO public.audit_events(id,tenant_id,action,object_type) VALUES($1,$2,'ci_checkpoint_append','fixture')",[id,tenant]);
  assert.deepEqual(await verifyHistoricalCheckpoint(reader,doc,publicKey),{verified:rows.length});
  await assert.rejects(()=>reader.query("DELETE FROM private.audit_chain_heads"),/permission denied/i);
  const modified=signCheckpoint(rows.map(r=>r.tenant_id===tenant?{...r,head_hash:"0".repeat(64)}:r),privateKey);
  await assert.rejects(()=>verifyHistoricalCheckpoint(reader,modified,publicKey),/Historical checkpoint mismatch/);
 }finally{await reader.query("RESET ROLE");reader.release();await Promise.all([admin.end(),app.end()]);}
});

test("containment alerts require sustained activity and clear without disclosing actor identifiers",()=>{
 const evaluate=createSecurityAlertPolicy(),normal={requests:100,authDenied:0,roleDenied:0,rateLimited:0,actorContained:0,unavailable:0,serverError:0,slow:0,aborted:0};
 const spike={...normal,rateLimited:5,actorContained:5};
 assert.deepEqual(evaluate(spike),[]);
 assert.deepEqual(evaluate(spike),[{event:"api_security_alert",category:"actor_containment_spike",state:"active"}]);
 assert.deepEqual(evaluate(spike),[]);
 assert.deepEqual(evaluate(normal),[{event:"api_security_alert",category:"actor_containment_spike",state:"cleared"}]);
});