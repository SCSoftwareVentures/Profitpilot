// Dedicated disposable PostgreSQL database only. Never point this test at production.
import test,{after,before} from "node:test";
import assert from "node:assert/strict";
import {randomUUID,randomBytes} from "node:crypto";
import {createPinCredential} from "../domain/pin-credential.mjs";
import {authorizeWithPin,authorizePayerInTransaction} from "./authorize-with-pin.mjs";
import {changePin,resolvePayer} from "./change-pin.mjs";
import {withPayer} from "./with-payer.mjs";
import {deriveCommandKey,reserveSigned,changePinSigned} from "./signed-commands.mjs";
import {createRecoveryVerifier,issueRecoveryGrant} from "./recovery-grant.mjs";
import {makeNotificationWorker} from "./notification-worker.mjs";
import {makeSandboxProvider} from "./sandbox-provider.mjs";
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
const recoveryKey=randomBytes(32);
const providerKey=randomBytes(32);
let payerPool, notificationPool, providerPool, provider;
before(async()=>{
  for(const name of ["securepay-milestones-draft.sql","securepay-release-proofs-draft.sql","securepay-customer-pins-draft.sql","securepay-payer-identity-draft.sql","securepay-payer-rls-draft.sql","securepay-command-boundary-draft.sql","securepay-recovery-grants-draft.sql","securepay-audit-draft.sql","securepay-session-revocation-draft.sql","securepay-notification-delivery-draft.sql","securepay-key-rotation-draft.sql","securepay-provider-sandbox-draft.sql"])
    await pool.query(await readFile(new URL(name,import.meta.url),"utf8"));
  await pool.query("INSERT INTO securepay_private.context_key(key_id,secret) VALUES('primary',$1)",[payerSigningKey]);
  await pool.query("INSERT INTO securepay_private.command_key(key_id,secret) VALUES('primary',$1)",[deriveCommandKey(pepper)]);
  await pool.query("INSERT INTO securepay_private.recovery_key(key_id,secret) VALUES('primary',$1)",[recoveryKey]);
  const password=randomBytes(32).toString("hex");
  await pool.query("ALTER ROLE securepay_payer_runtime LOGIN PASSWORD '"+password+"'");
  const payerUrl=new URL(url);payerUrl.username="securepay_payer_runtime";payerUrl.password=password;
  payerPool=new pg.Pool({connectionString:payerUrl.href,max:4,connectionTimeoutMillis:5000,statement_timeout:10000});
  const notificationPassword=randomBytes(32).toString("hex");
  await pool.query("ALTER ROLE securepay_notification_runtime LOGIN PASSWORD '"+notificationPassword+"'");
  const notificationUrl=new URL(url);notificationUrl.username="securepay_notification_runtime";notificationUrl.password=notificationPassword;
  notificationPool=new pg.Pool({connectionString:notificationUrl.href,max:4,connectionTimeoutMillis:5000,statement_timeout:10000});
  const providerPassword=randomBytes(32).toString("hex");
  await pool.query("ALTER ROLE securepay_provider_runtime LOGIN PASSWORD '"+providerPassword+"'");
  const providerUrl=new URL(url);providerUrl.username="securepay_provider_runtime";providerUrl.password=providerPassword;
  providerPool=new pg.Pool({connectionString:providerUrl.href,max:4,connectionTimeoutMillis:5000,statement_timeout:10000});
  await pool.query("INSERT INTO securepay_private.provider_key(key_id,secret) VALUES('primary',$1)",[providerKey]);
  provider=makeSandboxProvider({pool:providerPool,key:providerKey});
  await pool.query("CREATE TABLE securepay_ci_staff_only(secret text); INSERT INTO securepay_ci_staff_only VALUES ('fixture')");
  // Fixture admin bypasses RLS solely to exercise transaction semantics.
  // No permissive policies are installed; restricted role tested below.
  await pool.query("CREATE ROLE securepay_ci_restricted NOLOGIN NOBYPASSRLS");
  await pool.query("GRANT SELECT, INSERT, UPDATE ON securepay_milestones, securepay_release_requests, securepay_release_proofs, securepay_customer_pins, securepay_payer_identities, securepay_pin_change_grants TO securepay_ci_restricted");
});
after(async()=>{if(providerPool)await providerPool.end();if(notificationPool)await notificationPool.end();if(payerPool)await payerPool.end();await pool.end();});
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
async function identityFixture({funded=true}={}){
 const s=await fixture(), subject=randomUUID();
 await pool.query("INSERT INTO securepay_payer_identities(tenant_id,customer_id,auth_subject) VALUES($1,$2,$3)",[s.tenantId,s.customerId,subject]);
 const fundingRef=randomUUID();
 if(funded)assert.equal((await provider.event({...s,kind:"funded",fundingRef,amountCents:5000})).status,"applied");
 return {...s,subject,pin:"012345",fundingRef};
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
 });
 await assert.rejects(asPayer(s,c=>c.query("UPDATE securepay_milestones SET status='release_pending' WHERE id=$1",[other.milestoneId])),e=>e.code==="42501");
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

test("even with valid signed payer context, raw SQL cannot fabricate proofs, requests, PINs or grant consumption",async()=>{
 const s=await identityFixture();
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 const g=await changeGrant(s);
 const deny=(sql,args)=>assert.rejects(asPayer(s,c=>c.query(sql,args)),e=>e.code==="42501");
 await deny("INSERT INTO securepay_customer_pins(tenant_id,customer_id,salt,pin_hash) VALUES($1,$2,$3,$4)",[s.tenantId,s.customerId,"0".repeat(32),"0".repeat(64)]);
 await deny("UPDATE securepay_pin_change_grants SET consumed_at=clock_timestamp() WHERE grant_ref=$1",[g.grantRef]);
 assert.equal((await asPayer(s,c=>changePin(c,g,pepper))).ok,true);
 await deny("UPDATE securepay_customer_pins SET pin_hash=$3 WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId,"0".repeat(64)]);
 await deny("UPDATE securepay_customer_pins SET failed_attempts=0,locked_until=NULL WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 await deny("UPDATE securepay_milestones SET status='release_pending' WHERE id=$1",[s.milestoneId]);
 await deny("INSERT INTO securepay_release_proofs(proof_ref,tenant_id,milestone_id,customer_id,amount_cents,expires_at) VALUES($1,$2,$3,$4,5000,now()+interval '1 minute')",[randomUUID(),s.tenantId,s.milestoneId,s.customerId]);
 await deny("INSERT INTO securepay_release_requests(id,tenant_id,milestone_id,idempotency_key,amount_cents,authorization_ref,status) VALUES($1,$2,$3,$4,5000,$5,'pending')",[randomUUID(),s.tenantId,s.milestoneId,randomUUID(),randomUUID()]);
 await deny("SELECT secret FROM securepay_private.command_key",[]);
 assert.equal((await state(s)).requests,0);
});
test("signed database commands reject counterfeit authority and stale credentials, genuine PIN still reserves exactly once",async()=>{
 const s=await identityFixture();
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 const g=await changeGrant(s);
 const fake=randomBytes(32);
 const cred=await createPinCredential({...s,pin:s.pin,pepper:fake});
 const forged=await asPayer(s,c=>changePinSigned(c,{...s,grantRef:g.grantRef,purpose:"enroll",salt:cred.salt,pinHash:cred.pinHash},fake));
 assert.equal(forged.ok,false);
 assert.equal((await asPayer(s,c=>changePin(c,g,pepper))).ok,true);
 const {rows:[k]}=await pool.query("SELECT salt,pin_hash FROM securepay_customer_pins WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 const args={...s,amountCents:5000,version:0,requestId:randomUUID(),idempotencyKey:randomUUID(),salt:k.salt,pinHash:k.pin_hash};
 assert.equal((await asPayer(s,c=>reserveSigned(c,args,fake))).ok,false);
 assert.equal((await asPayer(s,c=>reserveSigned(c,{...args,version:1},pepper))).ok,false);
 assert.equal((await asPayer(s,c=>reserveSigned(c,{...args,pinHash:"0".repeat(64)},pepper))).ok,false);
 assert.equal((await state(s)).requests,0);
 assert.equal((await asPayer(s,c=>authorizePayerInTransaction(c,{...s,expectedAmountCents:5000,requestId:randomUUID(),idempotencyKey:randomUUID()},pepper))).ok,true);
 assert.equal((await asPayer(s,c=>reserveSigned(c,args,pepper))).ok,false);
 assert.equal((await state(s)).requests,1);
});

test("dedicated step-up tokens bind payer, tenant, operation and recent MFA; grant replay is atomic",async()=>{
 const {generateKeyPair,SignJWT}=await import("jose");
 const {makePayerService}=await import("../domain/payer-service.mjs");
 const s=await identityFixture();
 const {publicKey,privateKey}=await generateKeyPair("ES256");
 const issuer="https://recovery.invalid/",audience="securepay-recovery",requiredAcr="recovery-mfa";
 const verifyRecovery=createRecoveryVerifier({issuer,audience,requiredAcr,keyResolver:async()=>publicKey});
 const svc=makePayerService({pool:payerPool,signingKey:payerSigningKey,pepper,recoveryKey,verifyRecovery});
 const now=Math.floor(Date.now()/1000),jti=randomUUID();
 const token=async({sub=s.subject,aud=audience,tenant=s.tenantId,purpose="securepay-pin-enroll",acr=requiredAcr,auth=now,id=jti}={})=>
  new SignJWT({tenant_id:tenant,purpose,acr,auth_time:auth}).setProtectedHeader({alg:"ES256"})
  .setIssuer(issuer).setAudience(aud).setSubject(sub).setJti(id).setIssuedAt().setExpirationTime("2m").sign(privateKey);
 const call=(stepUpToken,purpose="enroll")=>svc.issueGrant({identity:{subject:s.subject,authTime:now},tenantId:s.tenantId,body:{purpose,stepUpToken}});
 for(const options of [{aud:"securepay-customer"},{sub:"another"},{tenant:randomUUID()},{purpose:"securepay-pin-recover"},{acr:"weak"},{auth:now-180}]){
  assert.equal((await call(await token(options))).ok,false);
 }
 const bearer=await token();
 const results=await Promise.all([call(bearer),call(bearer)]);
 assert.equal(results.filter(r=>r.ok).length,1);
 const g=results.find(r=>r.ok);
 assert.equal((await svc.setPin({identity:{subject:s.subject,authTime:now},tenantId:s.tenantId,body:{pin:s.pin,purpose:"enroll",grantRef:g.grantRef}})).ok,true);
 const recovery=await call(await token({id:randomUUID(),purpose:"securepay-pin-recover"}),"recover");
 assert.equal(recovery.ok,true);
 assert.equal((await svc.setPin({identity:{subject:s.subject,authTime:now},tenantId:s.tenantId,body:{pin:"654321",purpose:"recover",grantRef:recovery.grantRef}})).ok,true);
 assert.equal((await call(bearer)).ok,false);
});
test("recovery issuer key is inaccessible; ordinary signing authority cannot mint grants",async()=>{
 const s=await identityFixture(), assertion={digest:randomBytes(32).toString("hex"),expires:Math.floor(Date.now()/1000)+60};
 assert.equal((await asPayer(s,c=>issueRecoveryGrant(c,{...s,purpose:"enroll",assertion},deriveCommandKey(pepper)))).ok,false);
 await assert.rejects(asPayer(s,c=>c.query("SELECT secret FROM securepay_private.recovery_key")),e=>e.code==="42501");
 await assert.rejects(asPayer(s,c=>c.query("DELETE FROM securepay_private.recovery_assertions")),e=>e.code==="42501");
 assert.equal((await asPayer(s,c=>issueRecoveryGrant(c,{...s,purpose:"enroll",assertion},recoveryKey))).ok,true);
 assert.equal((await asPayer(s,c=>issueRecoveryGrant(c,{...s,purpose:"enroll",assertion},recoveryKey))).ok,false);
});
test("audit ledger records PIN failures and reservation atomically; payer cannot alter or inspect it",async()=>{
 const s=await identityFixture();
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 const g=await changeGrant(s);
 assert.equal((await asPayer(s,c=>changePin(c,g,pepper))).ok,true);
 const scope={...s,expectedAmountCents:5000,requestId:randomUUID(),idempotencyKey:randomUUID()};
 assert.equal((await asPayer(s,c=>authorizePayerInTransaction(c,{...scope,pin:"999999"},pepper))).ok,false);
 const good=await asPayer(s,c=>authorizePayerInTransaction(c,scope,pepper));assert.equal(good.ok,true);
 const {rows}=await pool.query("SELECT event_type,amount_cents,failure_count FROM securepay_private.audit_events WHERE tenant_id=$1 AND customer_id=$2 ORDER BY event_id",[s.tenantId,s.customerId]);
 assert.deepEqual(rows.map(r=>r.event_type),["grant_issued","grant_consumed","pin_enrolled","pin_failure","pin_counter_reset","release_reserved"]);
 assert.equal(rows[3].failure_count,1);assert.equal(rows[5].amount_cents,"5000");
 await assert.rejects(asPayer(s,c=>c.query("SELECT * FROM securepay_private.audit_events")),e=>e.code==="42501");
 await assert.rejects(asPayer(s,c=>c.query("DELETE FROM securepay_private.audit_events")),e=>e.code==="42501");
});

test("PIN recovery revokes prior sessions, queues notification atomically and requires fresh authentication",async()=>{
 const {makePayerService}=await import("../domain/payer-service.mjs");
 const s=await identityFixture();
 const svc=makePayerService({pool:payerPool,signingKey:payerSigningKey,pepper});
 const now=Math.floor(Date.now()/1000);
 const identity={subject:s.subject,authTime:now};
 const set=(g,pin=s.pin,id=identity)=>svc.setPin({identity:id,tenantId:s.tenantId,body:{pin,purpose:g.purpose,grantRef:g.grantRef}});
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 assert.equal((await set(await changeGrant(s))).ok,true);
 const g=await changeGrant(s,"recover");
 assert.equal((await set(g,"654321")).ok,true);
 const req={identity,tenantId:s.tenantId,milestoneId:s.milestoneId,body:{pin:"654321",expectedAmountCents:5000,idempotencyKey:randomUUID()}};
 assert.equal((await svc.reserve(req)).ok,false);
 assert.equal((await set(await changeGrant(s,"recover"),"654322")).ok,false);
 const {rows:[r]}=await pool.query("SELECT session_revoked_at FROM securepay_payer_identities WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 assert.ok(r.session_revoked_at.getTime()>=now*1000);
 const {rows}=await pool.query("SELECT event_type,delivered_at FROM securepay_private.recovery_notification_outbox WHERE tenant_id=$1 AND customer_id=$2 ORDER BY notification_id",[s.tenantId,s.customerId]);
 assert.deepEqual(rows,[{event_type:"pin_enrolled",delivered_at:null},{event_type:"pin_recovered",delivered_at:null}]);
 await assert.rejects(asPayer(s,c=>c.query("UPDATE securepay_payer_identities SET session_revoked_at=NULL WHERE tenant_id=$1",[s.tenantId])),e=>e.code==="42501");
 await assert.rejects(asPayer(s,c=>c.query("UPDATE securepay_private.recovery_notification_outbox SET delivered_at=now()")),e=>e.code==="42501");
 // JWT auth_time has whole-second resolution: wait for the next second.
 const next=Math.floor(r.session_revoked_at.getTime()/1000)+1;
 await new Promise(resolve=>setTimeout(resolve,Math.max(0,next*1000-Date.now()+20)));
 assert.equal((await svc.reserve({...req,identity:{subject:s.subject,authTime:Math.floor(Date.now()/1000)}})).ok,true);
 assert.equal((await state(s)).requests,1);
});

test("rollback of PIN recovery also rolls back revocation and notification intent",async()=>{
 const s=await identityFixture(),enroll=await changeGrant(s);
 assert.equal((await asPayer(s,c=>changePin(c,enroll,pepper))).ok,true);
 const g=await changeGrant(s,"recover");
 await assert.rejects(asPayer(s,async c=>{
  assert.equal((await changePin(c,{...g,pin:"654321"},pepper)).ok,true);
  throw Error("forced rollback");
 }),/forced rollback/);
 const {rows:[r]}=await pool.query("SELECT session_revoked_at FROM securepay_payer_identities WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 assert.equal(r.session_revoked_at,null);
 const {rows}=await pool.query("SELECT event_type FROM securepay_private.recovery_notification_outbox WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 assert.deepEqual(rows,[{event_type:"pin_enrolled"}]);
 assert.equal((await asPayer(s,c=>changePin(c,{...g,pin:"654321"},pepper))).ok,true);
});

async function notificationFixture(){
 // Preserve earlier audit assertions, but isolate notification worker tests from their backlog.
 await pool.query("UPDATE securepay_private.recovery_notification_outbox SET dead_lettered_at=clock_timestamp(),lease_id=NULL,lease_until=NULL WHERE delivered_at IS NULL AND dead_lettered_at IS NULL");
 const s=await identityFixture();
 const g=await changeGrant(s);
 assert.equal((await asPayer(s,c=>changePin(c,g,pepper))).ok,true);
 const {rows:[n]}=await pool.query("SELECT notification_id FROM securepay_private.recovery_notification_outbox WHERE tenant_id=$1 AND customer_id=$2",[s.tenantId,s.customerId]);
 return {...s,id:n.notification_id};
}
test("notification workers claim exactly once under concurrent execution and cannot access payment credentials",async()=>{
 const s=await notificationFixture(),calls=[];
 const worker=makeNotificationWorker({pool:notificationPool,namespace:"fixture",sink:{send:async m=>{calls.push(m);await new Promise(r=>setTimeout(r,30));return {reference:"receipt-1"};}}});
 const results=await Promise.all([worker.runOnce(),worker.runOnce()]);
 assert.deepEqual(results.map(r=>r.status).sort(),["delivered","idle"]);
 assert.equal(calls.length,1);
 assert.deepEqual(Object.keys(calls[0]).sort(),["customerId","eventType","idempotencyKey","tenantId"]);
 assert.equal(calls[0].customerId,s.customerId);
 assert.equal((await worker.runOnce()).status,"idle");
 await assert.rejects(notificationPool.query("SELECT * FROM public.securepay_customer_pins"),e=>e.code==="42501");
 await assert.rejects(notificationPool.query("SELECT * FROM securepay_private.recovery_notification_outbox"),e=>e.code==="42501");
 await assert.rejects(asPayer(s,c=>c.query("SELECT * FROM securepay_private.claim_notification($1)",[randomUUID()])),e=>e.code==="42501");
});
test("ambiguous notification failure reuses identical provider idempotency key and backs off",async()=>{
 const s=await notificationFixture(),keys=[],seen=new Set();
 const worker=makeNotificationWorker({pool:notificationPool,namespace:"fixture",sink:{send:async m=>{
  keys.push(m.idempotencyKey);
  if(!seen.has(m.idempotencyKey)){seen.add(m.idempotencyKey);throw Error("synthetic connection loss after delivery");}
  return {reference:"same-receipt"};
 }}});
 assert.equal((await worker.runOnce()).status,"retry_or_dead_letter");
 assert.equal((await worker.runOnce()).status,"idle");
 await pool.query("UPDATE securepay_private.recovery_notification_outbox SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE notification_id=$1",[s.id]);
 assert.equal((await worker.runOnce()).status,"delivered");
 assert.equal(keys.length,2);assert.equal(keys[0],keys[1]);assert.equal(seen.size,1);
 const {rows:[r]}=await pool.query("SELECT attempt_count,delivery_ref FROM securepay_private.recovery_notification_outbox WHERE notification_id=$1",[s.id]);
 assert.equal(r.attempt_count,2);assert.equal(r.delivery_ref,"same-receipt");
});
test("expired leases cannot acknowledge reclaimed notifications; exhausted retries dead-letter",async()=>{
 const s=await notificationFixture(),lease=randomUUID(),next=randomUUID();
 await notificationPool.query("SELECT * FROM securepay_private.claim_notification($1)",[lease]);
 await pool.query("UPDATE securepay_private.recovery_notification_outbox SET lease_until=clock_timestamp()-interval '1 second',attempt_count=7 WHERE notification_id=$1",[s.id]);
 const {rows:[job]}=await notificationPool.query("SELECT * FROM securepay_private.claim_notification($1)",[next]);
 assert.equal(job.notification_id,s.id);assert.equal(job.attempt_count,8);
 const finish=(l,ok,ref)=>notificationPool.query("SELECT securepay_private.finish_notification($1,$2,$3,$4) AS ok",[s.id,l,ok,ref]);
 assert.equal((await finish(lease,true,"stale")).rows[0].ok,false);
 assert.equal((await finish(next,false,null)).rows[0].ok,true);
 const {rows:[r]}=await pool.query("SELECT dead_lettered_at,delivered_at FROM securepay_private.recovery_notification_outbox WHERE notification_id=$1",[s.id]);
 assert.ok(r.dead_lettered_at);assert.equal(r.delivered_at,null);
 assert.equal((await notificationPool.query("SELECT * FROM securepay_private.claim_notification($1)",[randomUUID()])).rowCount,0);
});

test("separate authority process verifies JWT and PIN; gateway has no signing keys or payer database credentials",async()=>{
 const {default:express}=await import("express");
 const {createServer}=await import("node:http");
 const {generateKeyPair,exportJWK,SignJWT}=await import("jose");
 const {spawn}=await import("node:child_process");
 const {mkdtemp,rm}=await import("node:fs/promises");
 const {tmpdir}=await import("node:os");
 const {join}=await import("node:path");
 const {createSecurePayGateway,authoritySecrets}=await import("../../server/securepay-gateway.js");
 const s=await identityFixture();
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 const g=await changeGrant(s);
 const {publicKey,privateKey}=await generateKeyPair("ES256");
 const jwk=await exportJWK(publicKey);jwk.kid="fixture";jwk.alg="ES256";
 const jwks=createServer((req,res)=>{res.setHeader("content-type","application/json");res.end(JSON.stringify({keys:[jwk]}));});
 const listen=server=>new Promise(r=>server.listen(0,"127.0.0.1",r));
 const close=server=>new Promise(r=>server.close(r));
 await listen(jwks);
 const dir=await mkdtemp(join(tmpdir(),"sp-auth-")),socket=join(dir,"authority.sock");
 const gatewayEnv={NODE_ENV:"test",SECUREPAY_SANDBOX_ENABLED:"true",SECUREPAY_AUTHORITY_SOCKET:socket};
 for(const secret of authoritySecrets)assert.throws(()=>createSecurePayGateway({...gatewayEnv,[secret]:"forbidden"}),/secrets forbidden/);
 const issuer="https://authority-fixture.invalid/",audience="securepay-customer",acr="fixture-mfa";
 const child=spawn(process.execPath,["server/securepay-authority.js"],{env:{
  PATH:process.env.PATH,NODE_ENV:"test",SECUREPAY_SANDBOX_ENABLED:"true",SECUREPAY_AUTHORITY_SOCKET:socket,
  SECUREPAY_AUTH_ISSUER:issuer,SECUREPAY_AUTH_AUDIENCE:audience,SECUREPAY_AUTH_REQUIRED_ACR:acr,
  SECUREPAY_AUTH_JWKS_URL:"http://127.0.0.1:"+jwks.address().port+"/jwks",
  SECUREPAY_DATABASE_URL:payerPool.options.connectionString,SECUREPAY_CONTEXT_HMAC_SECRET:payerSigningKey.toString("hex"),SECUREPAY_PIN_PEPPER:pepper.toString("hex"),SECUREPAY_COMMAND_KEY:deriveCommandKey(pepper).toString("hex")
 },stdio:["ignore","pipe","pipe"]});
 const stopped=new Promise(r=>child.once("exit",r));
 const app=express();app.use("/v1/securepay",createSecurePayGateway(gatewayEnv));
 const gateway=createServer(app);
 try{
  await new Promise((resolve,reject)=>{
   let log="";const timer=setTimeout(()=>reject(Error("authority startup timeout")),5000);
   child.stdout.on("data",chunk=>{log+=chunk.toString();if(log.includes("authority ready")){clearTimeout(timer);resolve();}});
   child.once("exit",()=>{clearTimeout(timer);reject(Error("authority exited before ready"));});
   child.once("error",e=>{clearTimeout(timer);reject(e);});
  });
  await listen(gateway);
  const base="http://127.0.0.1:"+gateway.address().port+"/v1/securepay/tenants/"+s.tenantId;
  const token=async(sub=s.subject,aud=audience)=>new SignJWT({acr,auth_time:Math.floor(Date.now()/1000)})
   .setProtectedHeader({alg:"ES256",kid:"fixture"}).setIssuer(issuer).setAudience(aud).setSubject(sub).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  const post=(path,body,bearer)=>fetch(base+path,{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+bearer},body:JSON.stringify(body)});
  const bearer=await token(),pinBody={pin:s.pin,purpose:"enroll",grantRef:g.grantRef};
  assert.equal((await post("/pin",pinBody,await token(s.subject,"staff"))).status,401);
  assert.equal((await post("/pin",pinBody,await token("unknown"))).status,403);
  assert.equal((await post("/pin?debug=true",pinBody,bearer)).status,404);
  assert.equal((await post("/pin",{...pinBody,customerId:s.customerId},bearer)).status,400);
  assert.equal((await post("/pin",pinBody,bearer)).status,200);
  const route="/milestones/"+s.milestoneId+"/reserve",body={pin:s.pin,expectedAmountCents:5000,idempotencyKey:randomUUID()};
  assert.equal((await post(route,{...body,pin:"999999"},bearer)).status,403);
  const response=await post(route,body,bearer);
  assert.equal(response.status,202);
  const receipt=await response.json();assert.equal(receipt.moneyMoved,false);assert.equal(receipt.amountCents,"5000");
  assert.equal((await state(s)).requests,1);
  assert.equal((await post(route,body,bearer)).status,403);
  child.kill("SIGTERM");await stopped;
  const unavailable=await post(route,body,bearer);assert.equal(unavailable.status,503);
  assert.deepEqual(await unavailable.json(),{error:"SecurePay unavailable"});
  assert.equal((await state(s)).requests,1);
 }finally{
  if(child.exitCode===null&&child.signalCode===null){child.kill("SIGKILL");await stopped;}
  if(gateway.listening)await close(gateway);
  await close(jwks);await rm(dir,{recursive:true,force:true});
 }
});

test("signing key rotation supports overlap, then rejects revoked and expired context keys",async()=>{
 const s=await identityFixture(),next=randomBytes(32);
 await pool.query("INSERT INTO securepay_private.context_key(key_id,secret) VALUES('next',$1)",[next]);
 const old=()=>asPayer(s,c=>c.query("SELECT securepay_private.current_payer($1) AS payer",[s.tenantId]));
 const modern=()=>withPayer(payerPool,{...s,signingKey:next,contextKeyId:"next"},c=>c.query("SELECT securepay_private.current_payer($1) AS payer",[s.tenantId]));
 try{
  assert.equal((await old()).rows[0].payer,s.customerId);
  assert.equal((await modern()).rows[0].payer,s.customerId);
  await pool.query("UPDATE securepay_private.context_key SET active=false WHERE key_id='primary'");
  await assert.rejects(old(),/Payer context denied/);
  assert.equal((await modern()).rows[0].payer,s.customerId);
  await pool.query("UPDATE securepay_private.context_key SET valid_until=clock_timestamp()-interval '1 second' WHERE key_id='next'");
  await assert.rejects(modern(),/Payer context denied/);
 }finally{
  await pool.query("UPDATE securepay_private.context_key SET active=true WHERE key_id='primary'; DELETE FROM securepay_private.context_key WHERE key_id='next'");
 }
});
test("command key rotation leaves enrolled PIN intact and old command authority cannot reserve after revocation",async()=>{
 const s=await identityFixture(),next=randomBytes(32);
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 const g=await changeGrant(s);
 assert.equal((await asPayer(s,c=>changePin(c,g,pepper))).ok,true);
 await pool.query("INSERT INTO securepay_private.command_key(key_id,secret) VALUES('next',$1)",[next]);
 try{
  await pool.query("UPDATE securepay_private.command_key SET active=false WHERE key_id='primary'");
  const scope={...s,expectedAmountCents:5000,requestId:randomUUID(),idempotencyKey:randomUUID()};
  assert.equal((await asPayer(s,c=>authorizePayerInTransaction(c,scope,pepper))).ok,false);
  assert.equal((await state(s)).requests,0);
  assert.equal((await asPayer(s,c=>authorizePayerInTransaction(c,scope,pepper,{id:"next",key:next}))).ok,true);
  assert.equal((await state(s)).requests,1);
 }finally{
  await pool.query("UPDATE securepay_private.command_key SET active=true WHERE key_id='primary'; DELETE FROM securepay_private.command_key WHERE key_id='next'");
 }
});
test("recovery signing key rotation rejects retired key and cross-purpose key material",async()=>{
 const s=await identityFixture(),next=randomBytes(32);
 await pool.query("INSERT INTO securepay_private.recovery_key(key_id,secret) VALUES('next',$1)",[next]);
 const issue=(key,id)=>asPayer(s,c=>issueRecoveryGrant(c,{...s,purpose:"enroll",assertion:{digest:randomBytes(32).toString("hex"),expires:Math.floor(Date.now()/1000)+60}},key,id));
 try{
  assert.equal((await issue(recoveryKey,"primary")).ok,true);
  assert.equal((await issue(next,"next")).ok,true);
  await pool.query("UPDATE securepay_private.recovery_key SET active=false WHERE key_id='primary'");
  assert.equal((await issue(recoveryKey,"primary")).ok,false);
  assert.equal((await issue(deriveCommandKey(pepper),"next")).ok,false);
  assert.equal((await issue(next,"next")).ok,true);
  await assert.rejects(asPayer(s,c=>c.query("UPDATE securepay_private.recovery_key SET active=true")),e=>e.code==="42501");
 }finally{
  await pool.query("UPDATE securepay_private.recovery_key SET active=true WHERE key_id='primary'; DELETE FROM securepay_private.recovery_key WHERE key_id='next'");
 }
});

async function providerPayer({funded=false}={}){
 const s=await identityFixture({funded});
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 const g=await changeGrant(s);
 assert.equal((await asPayer(s,c=>changePin(c,g,pepper))).ok,true);
 const scope={...s,expectedAmountCents:5000,requestId:randomUUID(),idempotencyKey:randomUUID()};
 return {...s,scope};
}
const reserveProvider=s=>asPayer(s,c=>authorizePayerInTransaction(c,s.scope,pepper));
const providerEvent=(s,kind,extra={})=>provider.event({...s,kind,amountCents:5000,...extra});
test("valid customer PIN cannot reserve unfunded or held milestone; only verified exact provider funding allows reserve",async()=>{
 const s=await providerPayer();
 assert.equal((await reserveProvider(s)).ok,false);
 assert.equal((await state(s)).requests,0);
 const forged=makeSandboxProvider({pool:providerPool,key:randomBytes(32)});
 assert.equal((await forged.event({...s,kind:"funded",amountCents:5000})).status,"denied");
 assert.equal((await providerEvent(s,"funded",{amountCents:4999})).status,"denied");
 assert.equal((await providerEvent(s,"funded",{tenantId:randomUUID()})).status,"denied");
 await assert.rejects(asPayer(s,c=>c.query("SELECT * FROM securepay_private.provider_funding")),e=>e.code==="42501");
 await assert.rejects(providerPool.query("SELECT * FROM public.securepay_customer_pins"),e=>e.code==="42501");
 assert.equal((await providerEvent(s,"funded")).status,"applied");
 assert.equal((await providerEvent(s,"held")).status,"applied");
 assert.equal((await reserveProvider(s)).ok,false);
 assert.equal((await state(s)).requests,0);
 const valid=await providerPayer();
 assert.equal((await providerEvent(valid,"funded")).status,"applied");
 assert.equal((await reserveProvider(valid)).ok,true);
});
test("synthetic provider confirmation requires prior dispatch and exact scope; duplicate receipts apply once",async()=>{
 const s=await providerPayer({funded:true});
 const reserved=await reserveProvider(s);assert.equal(reserved.ok,true);
 const requestId=reserved.releaseRequestId, transactionRef=randomUUID(),eventId=randomUUID();
 const receipt={requestId,transactionRef,eventId};
 assert.equal((await providerEvent(s,"released",receipt)).status,"denied");
 assert.equal((await state(s)).status,"release_pending");
 const dispatch={...s,requestId};
 const results=await Promise.all([provider.beginDispatch(dispatch),provider.beginDispatch(dispatch)]);
 assert.equal(results.filter(x=>x.ok).length,1);
 assert.equal((await providerEvent(s,"released",{...receipt,requestId:randomUUID()})).status,"denied");
 assert.equal((await providerEvent(s,"released",{...receipt,amountCents:4999})).status,"denied");
 assert.equal((await providerEvent(s,"released",{...receipt,fundingRef:randomUUID()})).status,"denied");
 const answers=await Promise.all([providerEvent(s,"released",receipt),providerEvent(s,"released",receipt)]);
 assert.deepEqual(answers.map(x=>x.status).sort(),["applied","duplicate"]);
 assert.ok(answers.every(x=>x.moneyMoved===false));
 assert.equal((await providerEvent(s,"released",{...receipt,transactionRef:randomUUID()})).status,"denied");
 const {rows:[r]}=await pool.query("SELECT status,provider_transaction_ref FROM securepay_release_requests WHERE id=$1",[requestId]);
 assert.deepEqual(r,{status:"confirmed",provider_transaction_ref:transactionRef});
 assert.equal((await state(s)).status,"released");
 assert.equal((await state(s)).version,"2");
});
test("provider hold blocks pending dispatch; failed provider operation freezes reservation for reconciliation",async()=>{
 const s=await providerPayer({funded:true});
 const reserved=await reserveProvider(s);assert.equal(reserved.ok,true);
 assert.equal((await providerEvent(s,"held")).status,"applied");
 assert.equal((await provider.beginDispatch({...s,requestId:reserved.releaseRequestId})).ok,false);
 assert.equal((await state(s)).status,"release_pending");
 const other=await providerPayer({funded:true});
 const r=await reserveProvider(other);assert.equal(r.ok,true);
 const req={...other,requestId:r.releaseRequestId};
 assert.equal((await provider.beginDispatch(req)).ok,true);
 assert.equal((await providerEvent(other,"held")).status,"reconcile");
 assert.equal((await providerEvent(other,"failed",{requestId:r.releaseRequestId})).status,"applied");
 assert.equal((await provider.beginDispatch(req)).ok,false);
 assert.equal((await providerEvent(other,"released",{requestId:r.releaseRequestId,transactionRef:randomUUID()})).status,"denied");
 const {rows:[record]}=await pool.query("SELECT r.status,f.status AS funding_status FROM securepay_release_requests r JOIN securepay_private.provider_funding f ON f.milestone_id=r.milestone_id WHERE r.id=$1",[r.releaseRequestId]);
 assert.deepEqual(record,{status:"failed",funding_status:"held"});
 assert.equal((await state(other)).status,"release_pending");
});
