// Dedicated disposable PostgreSQL database only. Never point this test at production.
import test,{after,before} from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes} from "node:crypto";
import {createPinCredential} from "../domain/pin-credential.mjs";
import {authorizeWithPin} from "./authorize-with-pin.mjs";
import {readFile} from "node:fs/promises";
import pg from "pg";
import {reserveAuthorizedRelease} from "./reserve-authorized-release.mjs";
import {consumeReleaseProof} from "./consume-release-proof.mjs";

if(process.env.SECUREPAY_TEST_DATABASE !== "securepay_ci" || !process.env.SECUREPAY_TEST_DATABASE_URL)
  throw new Error("Disposable SecurePay CI database required");
const url=new URL(process.env.SECUREPAY_TEST_DATABASE_URL);
if(url.pathname!=="/securepay_ci"||!["localhost","127.0.0.1"].includes(url.hostname))
  throw new Error("Refusing non-local or non-CI database");
const pool=new pg.Pool({connectionString:url.href,max:8,connectionTimeoutMillis:5000,
  statement_timeout:10000});
before(async()=>{
  for(const name of ["securepay-milestones-draft.sql","securepay-release-proofs-draft.sql","securepay-customer-pins-draft.sql"])
    await pool.query(await readFile(new URL(name,import.meta.url),"utf8"));
  // Fixture admin bypasses RLS solely to exercise transaction semantics.
  // No permissive policies are installed; restricted role tested below.
  await pool.query("CREATE ROLE securepay_ci_restricted NOLOGIN NOBYPASSRLS");
  await pool.query("GRANT SELECT, INSERT, UPDATE ON securepay_milestones, securepay_release_requests, securepay_release_proofs, securepay_customer_pins TO securepay_ci_restricted");
});
after(async()=>pool.end());
async function fixture(status="approved",tenantId=randomUUID()) {
  const milestoneId=randomUUID(), customerId=randomUUID();
  await pool.query("INSERT INTO securepay_milestones(id,tenant_id,job_id,amount_cents,status) VALUES($1,$2,$3,5000,$4)",
    [milestoneId,tenantId,randomUUID(),status]);
  return {tenantId,milestoneId,customerId};
}
async function proof(scope,{expired=false}={}) {
  const authorizationRef=randomUUID();
  await pool.query("INSERT INTO securepay_release_proofs(proof_ref,tenant_id,milestone_id,customer_id,amount_cents,expires_at) VALUES($1,$2,$3,$4,5000,now()+$5::interval)",
    [authorizationRef,scope.tenantId,scope.milestoneId,scope.customerId,expired?"-1 minute":"5 minutes"]);
  return {...scope,authorizationRef,requestId:randomUUID(),idempotencyKey:randomUUID()};
}
async function state(scope) {
  const {rows:[r]}=await pool.query(`SELECT m.status,m.version,
    (SELECT count(*)::int FROM securepay_release_requests r WHERE r.milestone_id=m.id) AS requests,
    (SELECT count(*)::int FROM securepay_release_proofs p WHERE p.milestone_id=m.id AND p.consumed_at IS NOT NULL) AS consumed
    FROM securepay_milestones m WHERE id=$1`,[scope.milestoneId]);
  return r;
}
test("concurrent distinct valid proofs reserve exactly one payment",async()=>{
  const s=await fixture();
  const [a,b]=await Promise.all([proof(s),proof(s)]);
  // Hold the target row until both transactions have been initiated.
  const blocker=await pool.connect();
  let attempts;
  try {
    await blocker.query("BEGIN");
    await blocker.query("SELECT id FROM securepay_milestones WHERE id=$1 FOR UPDATE",[s.milestoneId]);
    attempts=Promise.allSettled([reserveAuthorizedRelease(pool,a),reserveAuthorizedRelease(pool,b)]);
    // Wait for two competing sessions to be blocked on the row lock.
    let waiting=false;
    for(let i=0;i<100;i++){
      const {rows:[r]}=await pool.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id, amount_cents, status FROM securepay_milestones%'");
      if(r.n>=2){waiting=true;break;}
      await new Promise(r=>setTimeout(r,25));
    }
    assert.equal(waiting,true,"both independent transactions must contend for the lock");
  } finally {
    await blocker.query("ROLLBACK");blocker.release();
  }
  const results=await attempts;
  assert.equal(results.filter(x=>x.status==="fulfilled").length,1);
  assert.match(results.find(x=>x.status==="rejected").reason.message,/not eligible/);
  assert.deepEqual(await state(s),{status:"release_pending",version:"1",requests:1,consumed:1});
});
test("same proof cannot be consumed concurrently",async()=>{
  const s=await fixture(), a=await proof(s);
  const scope={...a,amountCents:5000};
  const results=await Promise.all([consumeReleaseProof(pool,scope),consumeReleaseProof(pool,{...scope,requestId:randomUUID()})]);
  assert.equal(results.filter(Boolean).length,1);
  assert.equal((await state(s)).consumed,1);
});
test("unique request collision rolls proof consumption back",async()=>{
  const s=await fixture(), a=await proof(s);
  const other=await fixture("approved",s.tenantId), b=await proof(other);
  await reserveAuthorizedRelease(pool,b);
  await assert.rejects(reserveAuthorizedRelease(pool,{...a,idempotencyKey:b.idempotencyKey}),e=>e.code==="23505");
  assert.deepEqual(await state(s),{status:"approved",version:"0",requests:0,consumed:0});
  await reserveAuthorizedRelease(pool,a);
  assert.equal((await state(s)).requests,1);
});
test("expired proof, wrong customer, wrong tenant and disputed milestone cannot release",async()=>{
  const s=await fixture(), expired=await proof(s,{expired:true}), a=await proof(s);
  await assert.rejects(reserveAuthorizedRelease(pool,expired),/Authorization rejected/);
  await assert.rejects(reserveAuthorizedRelease(pool,{...a,customerId:randomUUID()}),/Authorization rejected/);
  await assert.rejects(reserveAuthorizedRelease(pool,{...a,tenantId:randomUUID()}),/not eligible/);
  const d=await fixture("disputed"), p=await proof(d);
  await assert.rejects(reserveAuthorizedRelease(pool,p),/not eligible/);
  assert.equal((await state(s)).requests,0);
  assert.equal((await state(d)).consumed,0);
});
test("draft RLS denies restricted role reads and mutations",async()=>{
  const s=await fixture();await proof(s);
  const c=await pool.connect();
  try {
    await c.query("BEGIN");
    await c.query("SET LOCAL ROLE securepay_ci_restricted");
    for(const table of ["securepay_milestones","securepay_release_requests","securepay_release_proofs","securepay_customer_pins"]){
      const {rows}=await c.query("SELECT * FROM "+table);
      assert.equal(rows.length,0);
    }
    const r=await c.query("UPDATE securepay_milestones SET status='released' WHERE id=$1",[s.milestoneId]);
    assert.equal(r.rowCount,0);
  }finally{await c.query("ROLLBACK");c.release();}
  assert.equal((await state(s)).status,"approved");
});

test("proof that expires while waiting for the milestone lock is rejected",async()=>{
  const s=await fixture(), a=await proof(s);
  const blocker=await pool.connect();
  let attempt;
  try {
    await blocker.query("BEGIN");
    await blocker.query("SELECT id FROM securepay_milestones WHERE id=$1 FOR UPDATE",[s.milestoneId]);
    await pool.query("UPDATE securepay_release_proofs SET expires_at=clock_timestamp()+interval '1 second' WHERE proof_ref=$1",[a.authorizationRef]);
    attempt=reserveAuthorizedRelease(pool,a).then(value=>({value}),error=>({error}));
    let waiting=false;
    for(let i=0;i<30;i++){
      const {rows:[r]}=await pool.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id, amount_cents, status FROM securepay_milestones%'");
      if(r.n>=1){waiting=true;break;}
      await new Promise(r=>setTimeout(r,20));
    }
    assert.equal(waiting,true);
    // Use the database clock rather than a client-side estimate.
    await pool.query("SELECT pg_sleep(GREATEST(0,extract(epoch FROM (expires_at-clock_timestamp())))+0.1) FROM securepay_release_proofs WHERE proof_ref=$1",[a.authorizationRef]);
  } finally {await blocker.query("ROLLBACK");blocker.release();}
  assert.match((await attempt).error?.message??"",/Authorization rejected/);
  assert.deepEqual(await state(s),{status:"approved",version:"0",requests:0,consumed:0});
});

const pepper=randomBytes(32);
async function pinFixture(){
 const s=await fixture(),pin="012345";
 const cred=await createPinCredential({...s,pin,pepper});
 await pool.query("INSERT INTO securepay_customer_pins(tenant_id,customer_id,salt,pin_hash) VALUES($1,$2,$3,$4)",[s.tenantId,s.customerId,cred.salt,cred.pinHash]);
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 return {...s,pin,expectedAmountCents:5000};
}
const attempt=(s,patch={})=>authorizeWithPin(pool,{...s,requestId:randomUUID(),idempotencyKey:randomUUID(),...patch},pepper);
test("real PIN reserves only the agreed amount for the identified payer and cannot be replayed",async()=>{
 const s=await pinFixture();
 assert.equal((await attempt(s,{expectedAmountCents:5001})).ok,false);
 assert.equal((await attempt(s,{customerId:randomUUID()})).ok,false);
 assert.equal((await attempt(s,{tenantId:randomUUID()})).ok,false);
 assert.equal((await state(s)).requests,0);
 const r=await attempt(s);
 assert.equal(r.ok,true);
 assert.equal((await attempt(s)).ok,false);
 const persisted=await state(s);
 assert.equal(persisted.status,"release_pending");
 assert.equal(persisted.requests,1);
 assert.equal(persisted.consumed,1);
});
test("concurrent wrong PINs persist failed attempts and lock out valid PIN until expiry",async()=>{
 const s=await pinFixture();
 const failures=await Promise.all(Array.from({length:6},()=>attempt(s,{pin:"999999"})));
 assert.equal(failures.every(x=>!x.ok),true);
 const {rows:[locked]}=await pool.query("SELECT failed_attempts,locked_until>clock_timestamp() AS locked FROM securepay_customer_pins WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 assert.deepEqual(locked,{failed_attempts:5,locked:true});
 assert.equal((await attempt(s)).ok,false);
 assert.equal((await state(s)).requests,0);
 await pool.query("UPDATE securepay_customer_pins SET locked_until=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 assert.equal((await attempt(s)).ok,true);
 const {rows:[after]}=await pool.query("SELECT failed_attempts,locked_until FROM securepay_customer_pins WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 assert.deepEqual(after,{failed_attempts:0,locked_until:null});
});
test("concurrent correct PIN requests reserve a single release",async()=>{
 const s=await pinFixture();
 const results=await Promise.all([attempt(s),attempt(s)]);
 assert.equal(results.filter(x=>x.ok).length,1);
 assert.equal((await state(s)).requests,1);
});
