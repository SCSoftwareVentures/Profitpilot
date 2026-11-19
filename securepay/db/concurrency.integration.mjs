// Dedicated disposable PostgreSQL database only. Never point this test at production.
import test,{after,before} from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
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
  for(const name of ["securepay-milestones-draft.sql","securepay-release-proofs-draft.sql"])
    await pool.query(await readFile(new URL(name,import.meta.url),"utf8"));
  // Fixture admin bypasses RLS solely to exercise transaction semantics.
  // No permissive policies are installed; restricted role tested below.
  await pool.query("CREATE ROLE securepay_ci_restricted NOLOGIN NOBYPASSRLS");
  await pool.query("GRANT SELECT, INSERT, UPDATE ON securepay_milestones, securepay_release_requests, securepay_release_proofs TO securepay_ci_restricted");
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
      const {rows:[r]}=await blocker.query("SELECT count(*)::int AS n FROM pg_stat_activity WHERE pid<>pg_backend_pid() AND datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id, amount_cents, status FROM securepay_milestones%'");
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
    for(const table of ["securepay_milestones","securepay_release_requests","securepay_release_proofs"]){
      const {rows}=await c.query("SELECT * FROM "+table);
      assert.equal(rows.length,0);
    }
    const r=await c.query("UPDATE securepay_milestones SET status='released' WHERE id=$1",[s.milestoneId]);
    assert.equal(r.rowCount,0);
  }finally{await c.query("ROLLBACK");c.release();}
  assert.equal((await state(s)).status,"approved");
});
