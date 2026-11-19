// Dedicated disposable PostgreSQL database only. Never point this test at production.
import test,{after,before} from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes} from "node:crypto";
import {createPinCredential} from "../domain/pin-credential.mjs";
import {authorizeWithPin,authorizePayerInTransaction} from "./authorize-with-pin.mjs";
import {changePin,resolvePayer} from "./change-pin.mjs";
import {withPayer} from "./with-payer.mjs";
import {verifyPinCredential} from "../domain/pin-credential.mjs";
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
const payerSigningKey=randomBytes(32);
let payerPool;
before(async()=>{
  for(const name of ["securepay-milestones-draft.sql","securepay-release-proofs-draft.sql","securepay-customer-pins-draft.sql","securepay-payer-identity-draft.sql","securepay-payer-rls-draft.sql"])
    await pool.query(await readFile(new URL(name,import.meta.url),"utf8"));
  await pool.query("INSERT INTO securepay_private.context_key(singleton,secret) VALUES(true,$1)",[payerSigningKey]);
  const password=randomBytes(32).toString("hex");
  await pool.query("ALTER ROLE securepay_payer_runtime LOGIN PASSWORD '"+password+"'");
  const payerUrl=new URL(url);payerUrl.username="securepay_payer_runtime";payerUrl.password=password;
  payerPool=new pg.Pool({connectionString:payerUrl.href,max:4,connectionTimeoutMillis:5000,statement_timeout:10000});
  await pool.query("CREATE TABLE securepay_ci_staff_only(secret text); INSERT INTO securepay_ci_staff_only VALUES ('fixture')");
  // Fixture admin bypasses RLS solely to exercise transaction semantics.
  // No permissive policies are installed; restricted role tested below.
  await pool.query("CREATE ROLE securepay_ci_restricted NOLOGIN NOBYPASSRLS");
  await pool.query("GRANT SELECT, INSERT, UPDATE ON securepay_milestones, securepay_release_requests, securepay_release_proofs, securepay_customer_pins, securepay_payer_identities, securepay_pin_change_grants TO securepay_ci_restricted");
});
after(async()=>{if(payerPool)await payerPool.end();await pool.end();});
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
    for(const table of ["securepay_milestones","securepay_release_requests","securepay_release_proofs","securepay_customer_pins","securepay_payer_identities","securepay_pin_change_grants"]){
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

async function tx(fn){
 const c=await pool.connect();
 try{await c.query("BEGIN");const r=await fn(c);await c.query("COMMIT");return r;}
 catch(e){await c.query("ROLLBACK");throw e;}
 finally{c.release();}
}
async function identityFixture(){
 const s=await fixture(), subject=randomUUID();
 await pool.query("INSERT INTO securepay_payer_identities(tenant_id,customer_id,auth_subject) VALUES($1,$2,$3)",[s.tenantId,s.customerId,subject]);
 return {...s,subject,pin:"012345"};
}
async function changeGrant(s,purpose="enroll",expired=false){
 const grantRef=randomUUID();
 await pool.query("INSERT INTO securepay_pin_change_grants(grant_ref,tenant_id,customer_id,purpose,expires_at) VALUES($1,$2,$3,$4,clock_timestamp()+$5::interval)",[grantRef,s.tenantId,s.customerId,purpose,expired?"-1 minute":"5 minutes"]);
 return {...s,purpose,grantRef};
}
const change=(s)=>tx(c=>changePin(c,s,pepper));
test("payer identity is scoped to active verified subject and tenant",async()=>{
 const s=await identityFixture();
 assert.equal(await tx(c=>resolvePayer(c,s)),s.customerId);
 assert.equal(await tx(c=>resolvePayer(c,{...s,subject:"other"})),null);
 assert.equal(await tx(c=>resolvePayer(c,{...s,tenantId:randomUUID()})),null);
 await pool.query("UPDATE securepay_payer_identities SET active=false WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 assert.equal(await tx(c=>resolvePayer(c,s)),null);
});
test("PIN enrollment requires matching current grant and is single-use even under concurrency",async()=>{
 const s=await identityFixture(),g=await changeGrant(s);
 assert.equal((await change({...g,subject:"admin"})).ok,false);
 assert.equal((await change({...g,tenantId:randomUUID()})).ok,false);
 assert.equal((await change({...g,purpose:"recover"})).ok,false);
 assert.equal((await change(await changeGrant(s,"enroll",true))).ok,false);
 const results=await Promise.all([change(g),change(g)]);
 assert.equal(results.filter(x=>x.ok).length,1);
 assert.equal((await change(await changeGrant(s))).ok,false);
});
test("PIN recovery requires separate grant, invalidates unused approvals, and replaces credential",async()=>{
 const s=await identityFixture();assert.equal((await change(await changeGrant(s))).ok,true);
 const p=await proof(s),g=await changeGrant(s,"recover");
 const next={...g,pin:"654321"};
 assert.equal((await change(next)).ok,true);
 assert.equal((await change(next)).ok,false);
 const {rows:[k]}=await pool.query("SELECT salt,pin_hash,failed_attempts,locked_until FROM securepay_customer_pins WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 assert.equal(await verifyPinCredential({...s,pepper},{salt:k.salt,pinHash:k.pin_hash}),false);
 assert.equal(await verifyPinCredential({...s,pin:next.pin,pepper},{salt:k.salt,pinHash:k.pin_hash}),true);
 assert.equal((await pool.query("SELECT 1 FROM securepay_release_proofs WHERE proof_ref=$1",[p.authorizationRef])).rowCount,0);
 assert.equal(k.failed_attempts,0);assert.equal(k.locked_until,null);
});

test("verified-subject release ignores supplied customer ID and denies inactive payer",async()=>{
 const s=await identityFixture();
 assert.equal((await change(await changeGrant(s))).ok,true);
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 const release=(patch={})=>tx(c=>authorizePayerInTransaction(c,{...s,expectedAmountCents:5000,requestId:randomUUID(),idempotencyKey:randomUUID(),...patch},pepper));
 assert.equal((await release({subject:"forged",customerId:s.customerId})).ok,false);
 await pool.query("UPDATE securepay_payer_identities SET active=false WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 assert.equal((await release()).ok,false);
 await pool.query("UPDATE securepay_payer_identities SET active=true WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 assert.equal((await release({customerId:randomUUID()})).ok,true);
 assert.equal((await state(s)).requests,1);
});

const asPayer=(s,fn)=>withPayer(payerPool,{tenantId:s.tenantId,subject:s.subject,signingKey:payerSigningKey},fn);
test("restricted payer cannot read without signature, forge context, or access staff data",async()=>{
 assert.equal((await payerPool.query("SELECT * FROM securepay_milestones")).rowCount,0);
 const s=await identityFixture();
 await assert.rejects(withPayer(pool,{...s,signingKey:payerSigningKey},async()=>true),/Incorrect payer runtime role/);
 await assert.rejects(withPayer(payerPool,{...s,signingKey:randomBytes(32)},async()=>true),/Payer context denied/);
 await assert.rejects(asPayer({...s,subject:"not-the-payer"},async()=>true),/Payer context denied/);
 await assert.rejects(asPayer(s,c=>c.query("SELECT * FROM securepay_ci_staff_only")),e=>e.code==="42501");
 await assert.rejects(asPayer(s,c=>c.query("SELECT secret FROM securepay_private.context_key")),e=>e.code==="42501");
});
test("signed payer runtime isolates same-tenant and cross-tenant customers and executes genuine PIN reservation",async()=>{
 const s=await identityFixture();
 const other=await fixture("approved",s.tenantId);
 await pool.query("INSERT INTO securepay_payer_identities(tenant_id,customer_id,auth_subject) VALUES($1,$2,$3)",[other.tenantId,other.customerId,randomUUID()]);
 const foreign=await identityFixture();
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=CASE WHEN id=$1 THEN $2::uuid WHEN id=$3 THEN $4::uuid ELSE $6::uuid END WHERE id IN ($1,$3,$5)",[s.milestoneId,s.customerId,other.milestoneId,other.customerId,foreign.milestoneId,foreign.customerId]);
 await asPayer(s,async c=>{
  const x=await c.query("SELECT id FROM securepay_milestones");
  assert.deepEqual(x.rows,[{id:s.milestoneId}]);
  assert.equal((await c.query("UPDATE securepay_milestones SET status='release_pending' WHERE id=$1",[other.milestoneId])).rowCount,0);
 });
 await assert.rejects(asPayer(s,c=>c.query("UPDATE securepay_milestones SET amount_cents=1 WHERE id=$1",[s.milestoneId])),e=>e.code==="42501");
 await assert.rejects(asPayer(s,c=>c.query("UPDATE securepay_milestones SET status='released' WHERE id=$1",[s.milestoneId])),e=>e.code==="42501");
 const grant=await changeGrant(s);
 assert.equal((await asPayer(s,c=>changePin(c,grant,pepper))).ok,true);
 const result=await asPayer(s,c=>authorizePayerInTransaction(c,{...s,expectedAmountCents:5000,requestId:randomUUID(),idempotencyKey:randomUUID()},pepper));
 assert.equal(result.ok,true);
 assert.equal((await state(s)).requests,1);
 assert.equal((await state(other)).status,"approved");
 assert.equal((await state(foreign)).status,"approved");
});

test("sandbox HTTP routes require customer audience, recent MFA and real PIN; deny spoofing and cross-payer access",async()=>{
 const {default:express}=await import("express");
 const {createServer}=await import("node:http");
 const {generateKeyPair,SignJWT}=await import("jose");
 const {createSecurePayRouter,createPayerTokenVerifier,createSecurePayRouterFromEnv}=await import("../../server/securepay-router.js");
 const {makePayerService}=await import("../domain/payer-service.mjs");
 const s=await identityFixture(), other=await identityFixture();
 const grant=await changeGrant(s);
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[other.milestoneId,other.customerId]);
 const {publicKey,privateKey}=await generateKeyPair("ES256");
 const issuer="https://fixture.invalid/",audience="securepay-customer",requiredAcr="fixture-mfa";
 const verifyToken=createPayerTokenVerifier({issuer,audience,requiredAcr,keyResolver:async()=>publicKey});
 const app=express();
 app.use("/disabled",createSecurePayRouterFromEnv({NODE_ENV:"production",SECUREPAY_SANDBOX_ENABLED:"true"}));
 app.use("/sandbox",createSecurePayRouter({enabled:true,verifyToken,
   service:makePayerService({pool:payerPool,signingKey:payerSigningKey,pepper})}));
 const api=createServer(app);
 await new Promise(r=>api.listen(0,"127.0.0.1",r));
 const base="http://127.0.0.1:"+api.address().port;
 const now=Math.floor(Date.now()/1000);
 const token=async({sub=s.subject,aud=audience,acr=requiredAcr,authTime=now}={})=>
  new SignJWT({acr,auth_time:authTime}).setProtectedHeader({alg:"ES256"}).setIssuer(issuer)
   .setAudience(aud).setSubject(sub).setIssuedAt().setExpirationTime("5m").sign(privateKey);
 const pinPath="/sandbox/tenants/"+s.tenantId+"/pin";
 const releasePath="/sandbox/tenants/"+s.tenantId+"/milestones/"+s.milestoneId+"/reserve";
 const post=(path,body,bearer)=>fetch(base+path,{method:"POST",headers:{"content-type":"application/json",...(bearer?{authorization:"Bearer "+bearer}:{})},body:JSON.stringify(body)});
 const pinBody={pin:s.pin,purpose:"enroll",grantRef:grant.grantRef};
 const releaseBody={pin:s.pin,expectedAmountCents:5000,idempotencyKey:randomUUID()};
 try {
  assert.equal((await post(pinPath,pinBody)).status,401);
  assert.equal((await post(pinPath,pinBody,await token({aud:"profitpilot-api"}))).status,401);
  assert.equal((await post(pinPath,pinBody,await token({acr:"password-only"}))).status,401);
  assert.equal((await post(pinPath,pinBody,await token({authTime:now-600}))).status,401);
  assert.equal((await post(pinPath,pinBody,await token({sub:other.subject}))).status,403);
  const bearer=await token();
  assert.equal((await post(pinPath.replace("/sandbox","/disabled"),pinBody,bearer)).status,404);
  assert.equal((await post(pinPath,{...pinBody,customerId:s.customerId},bearer)).status,400);
  const enrolled=await post(pinPath,pinBody,bearer);
  assert.equal(enrolled.status,200);assert.equal(enrolled.headers.get("cache-control"),"no-store");
  assert.deepEqual(await enrolled.json(),{mode:"sandbox",status:"pin_updated"});
  assert.equal((await post(releasePath,{...releaseBody,pin:"999999"},bearer)).status,403);
  assert.equal((await post(releasePath,{...releaseBody,expectedAmountCents:5001},bearer)).status,403);
  assert.equal((await post(releasePath,{...releaseBody,customerId:s.customerId},bearer)).status,400);
  assert.equal((await post(releasePath,releaseBody,await token({sub:other.subject}))).status,403);
  const reserved=await post(releasePath,releaseBody,bearer);
  assert.equal(reserved.status,202);
  const body=await reserved.json();
  assert.equal(body.mode,"sandbox");assert.equal(body.status,"reserved");assert.equal(body.moneyMoved,false);
  assert.equal(body.amountCents,"5000");assert.equal(body.milestoneId,s.milestoneId);
  assert.equal(Object.hasOwn(body,"authorizationRef"),false);
  assert.equal((await post(releasePath,releaseBody,bearer)).status,403);
  assert.equal((await state(s)).requests,1);
 }finally{await new Promise(resolve=>api.close(resolve));}
});
