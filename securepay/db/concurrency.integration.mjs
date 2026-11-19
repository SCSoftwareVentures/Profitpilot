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
import {makeDisputeActor,makeSettlementAuthorizer,makeSettlementProvider} from "./dispute-settlement.mjs";
import {makeRectificationActor,scanDisputeDeadlines,purgeExpiredEvidence} from "./rectification.mjs";
import {makeEvidenceScanner,crc32,validEvidencePNG} from "./evidence-scanner.mjs";
import {makeWorkCompletionOwner} from "./work-completion.mjs";
import {makeSharedCustomerBudget} from "./shared-budget.mjs";
import {createHash} from "node:crypto";
import {deflateSync} from "node:zlib";
import {verifyAuditChain} from "./audit-chain.mjs";
import {loadReconciliationReport,summarizeReport,renderReconciliationDashboard,signReport,verifySignedReport,reportCSV} from "./reconciliation-report.mjs";
import {prepareRecovery,signProviderRecovery,signReviewerRecovery,applyRecovery} from "./settlement-recovery.mjs";
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
let payerPool, notificationPool, providerPool, provider, disputePool, settlementPool, escalationPool, auditPool, retentionPool, reconciliationPool, reportingPool, completionPool;
const scanKey=randomBytes(32);
const scanner=makeEvidenceScanner({key:scanKey,scan:async()=>"clean"});
before(async()=>{
  for(const name of ["securepay-milestones-draft.sql","securepay-release-proofs-draft.sql","securepay-customer-pins-draft.sql","securepay-payer-identity-draft.sql","securepay-payer-rls-draft.sql","securepay-command-boundary-draft.sql","securepay-recovery-grants-draft.sql","securepay-audit-draft.sql","securepay-session-revocation-draft.sql","securepay-notification-delivery-draft.sql","securepay-key-rotation-draft.sql","securepay-provider-sandbox-draft.sql","securepay-dispute-settlement-draft.sql","securepay-rectification-draft.sql","securepay-evidence-encryption-draft.sql","securepay-audit-chain-draft.sql","securepay-evidence-screening-retention-draft.sql","securepay-normalized-evidence-draft.sql","securepay-shared-rate-limit-draft.sql","securepay-settlement-legs-draft.sql","securepay-financial-journal-draft.sql","securepay-settlement-recovery-draft.sql","securepay-reporting-draft.sql","securepay-portal-draft.sql","securepay-work-completion-draft.sql","securepay-work-revision-draft.sql","securepay-payment-plan-draft.sql"])
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
  async function rolePool(role){
   const password=randomBytes(32).toString("hex");
   await pool.query("ALTER ROLE "+role+" LOGIN PASSWORD '"+password+"'");
   const u=new URL(url);u.username=role;u.password=password;
   return new pg.Pool({connectionString:u.href,max:4,connectionTimeoutMillis:5000,statement_timeout:10000});
  }
  disputePool=await rolePool("securepay_dispute_runtime");
  settlementPool=await rolePool("securepay_settlement_runtime");
  escalationPool=await rolePool("securepay_escalation_runtime");
  auditPool=await rolePool("securepay_audit_runtime");
  retentionPool=await rolePool("securepay_retention_runtime");
  reconciliationPool=await rolePool("securepay_reconciliation_runtime");
  reportingPool=await rolePool("securepay_reporting_runtime");
  completionPool=await rolePool("securepay_completion_runtime");
  await pool.query("INSERT INTO securepay_private.evidence_scan_keys(key_id,secret) VALUES('primary',$1)",[scanKey]);
  await pool.query("INSERT INTO securepay_private.evidence_keys(key_id,secret,write_enabled) VALUES('primary',$1,true)",[randomBytes(32)]);
  await pool.query("CREATE TABLE securepay_ci_staff_only(secret text); INSERT INTO securepay_ci_staff_only VALUES ('fixture')");
  // Fixture admin bypasses RLS solely to exercise transaction semantics.
  // No permissive policies are installed; restricted role tested below.
  await pool.query("CREATE ROLE securepay_ci_restricted NOLOGIN NOBYPASSRLS");
  await pool.query("GRANT SELECT, INSERT, UPDATE ON securepay_milestones, securepay_release_requests, securepay_release_proofs, securepay_customer_pins, securepay_payer_identities, securepay_pin_change_grants TO securepay_ci_restricted");
});
after(async()=>{if(completionPool)await completionPool.end();if(reportingPool)await reportingPool.end();if(reconciliationPool)await reconciliationPool.end();if(retentionPool)await retentionPool.end();if(auditPool)await auditPool.end();if(escalationPool)await escalationPool.end();if(disputePool)await disputePool.end();if(settlementPool)await settlementPool.end();if(providerPool)await providerPool.end();if(notificationPool)await notificationPool.end();if(payerPool)await payerPool.end();await pool.end();});
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
async function identityFixture({funded=true,approved=true}={}){
 const s=await fixture(approved?"approved":"planned"), subject=randomUUID();
 await pool.query("INSERT INTO securepay_payer_identities(tenant_id,customer_id,auth_subject) VALUES($1,$2,$3)",[s.tenantId,s.customerId,subject]);
 // Prior tests are focused on other security layers and need an already-approved
 // completion at version zero. This privileged disposable fixture is not an API.
 if(approved)await seedApprovedWork(s);
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
  SECUREPAY_DATABASE_URL:payerPool.options.connectionString,SECUREPAY_CONTEXT_HMAC_SECRET:payerSigningKey.toString("hex"),SECUREPAY_PIN_PEPPER:pepper.toString("hex"),SECUREPAY_COMMAND_KEY:deriveCommandKey(pepper).toString("hex"),SECUREPAY_RATE_LIMIT_KEY:randomBytes(32).toString("hex")
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
  const viewRoute="/milestones/"+s.milestoneId+"/view";
  const page=await fetch("http://127.0.0.1:"+gateway.address().port+"/v1/securepay/portal");
  assert.equal(page.status,200);assert.match(page.headers.get("content-security-policy"),/sha256-/);assert.match(await page.text(),/SANDBOX ONLY/);
  const read=await post(viewRoute,{},bearer);assert.equal(read.status,200);
  assert.deepEqual(await read.json(),{mode:"sandbox",moneyMoved:false,milestoneId:s.milestoneId,amountCents:"5000",status:"approved",fundingStatus:"funded",isFinal:false,requestStatus:null});
  const completionResponse=await post("/milestones/"+s.milestoneId+"/completion",{},bearer);
  assert.equal(completionResponse.status,200);const completion=await completionResponse.json();assert.equal(completion.status,"approved");assert.equal(completion.photos.length,1);assert.equal(completion.amountCents,"5000");
  const photoResponse=await post("/milestones/"+s.milestoneId+"/photo",{photoId:completion.photos[0].photoId},bearer);assert.equal(photoResponse.status,200);
  const photo=await photoResponse.json();assert.equal(photo.digest,completion.photos[0].digest);assert.equal(validEvidencePNG(Buffer.from(photo.content,"base64")),true);
  assert.equal((await post("/milestones/"+s.milestoneId+"/photo",{photoId:randomUUID()},bearer)).status,403);
  assert.equal((await post(viewRoute,{customerId:s.customerId},bearer)).status,400);
  assert.equal((await post(viewRoute,{},await token("unknown"))).status,403);
  assert.equal((await post("/milestones/"+randomUUID()+"/view",{},bearer)).status,403);
  const route="/milestones/"+s.milestoneId+"/reserve",body={pin:s.pin,expectedAmountCents:5000,idempotencyKey:randomUUID()};
  assert.equal((await post(route,{...body,pin:"999999"},bearer)).status,403);
  const response=await post(route,body,bearer);
  assert.equal(response.status,202);
  const receipt=await response.json();assert.equal(receipt.moneyMoved,false);assert.equal(receipt.amountCents,"5000");
  assert.equal((await state(s)).requests,1);
  const pending=await post(viewRoute,{},bearer);assert.equal(pending.status,200);const updated=await pending.json();assert.equal(updated.status,"release_pending");assert.equal(updated.requestStatus,"pending");
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
 const reconciliation=await pool.query("SELECT reason FROM securepay_private.provider_reconciliation WHERE tenant_id=$1 AND milestone_id=$2 ORDER BY opened_at",[other.tenantId,other.milestoneId]);
 assert.deepEqual(reconciliation.rows.map(r=>r.reason),["hold_after_dispatch","provider_failure"]);
 assert.equal((await state(other)).status,"release_pending");
});

async function disputeFixture(){
 const s=await providerPayer({funded:true}),caseId=randomUUID(),settlementId=randomUUID();
 const scope={tenantId:s.tenantId,milestoneId:s.milestoneId,caseId};
 async function actor(role,actorId=randomUUID()){
  const key=randomBytes(32);
  await pool.query("INSERT INTO securepay_private.dispute_actors(tenant_id,actor_id,role,secret) VALUES($1,$2,$3,$4)",[s.tenantId,actorId,role,key]);
  return {actorId,key,service:makeDisputeActor({pool:disputePool,key,actorId}),repairService:makeRectificationActor({pool:disputePool,key,actorId,scanner})};
 }
 const customer=await actor("customer",s.customerId),owner=await actor("owner"),reviewer=await actor("reviewer"),second=await actor("reviewer"),authorizer=await actor("settlement");
 await pool.query("INSERT INTO securepay_private.dispute_parties(tenant_id,milestone_id,owner_id) VALUES($1,$2,$3)",[s.tenantId,s.milestoneId,owner.actorId]);
 const call=(actor,action,details,extra={})=>actor.service.action({...scope,action,details,...extra});
 const digest=randomBytes(32).toString("hex"),amounts={payoutCents:3000,refundCents:2000};
 const settlement={...scope,settlementId,...amounts};
 const approval=makeSettlementAuthorizer({pool:settlementPool,key:authorizer.key,actorId:authorizer.actorId});
 const confirm=makeSettlementProvider({pool:providerPool,key:providerKey});
 return {s,scope,settlement,customer,owner,reviewer,second,authorizer,call,digest,amounts,approval,confirm};
}
const openCase=d=>d.call(d.customer,"open","moderate",{evidenceDigest:d.digest});
const evidence=d=>d.call(d.owner,"evidence","Owner supporting material",{evidenceDigest:d.digest});
const decide=(d,amounts=d.amounts)=>d.call(d.reviewer,"decide","Reasoned provisional decision",{...amounts,evidenceDigest:d.digest});
const finalize=(d,amounts=d.amounts)=>d.call(d.second,"finalize","Independent final review",{...amounts,evidenceDigest:d.digest});
test("independent dispute hold blocks ordinary dispatch and requires both parties' evidence and separate final reviewer",async()=>{
 const d=await disputeFixture(),r=await reserveProvider(d.s);assert.equal(r.ok,true);
 assert.equal((await d.call(d.owner,"open","moderate",{evidenceDigest:d.digest})).ok,false);
 assert.equal((await openCase(d)).ok,true);
 assert.equal((await state(d.s)).status,"disputed");
 assert.equal((await provider.beginDispatch({...d.s,requestId:r.releaseRequestId})).ok,false);
 assert.equal((await reserveProvider(d.s)).ok,false);
 assert.equal((await decide(d)).ok,false);
 assert.equal((await evidence(d)).ok,true);
 assert.equal((await d.call(d.owner,"decide","Owner cannot adjudicate",{...d.amounts,evidenceDigest:d.digest})).ok,false);
 assert.equal((await decide(d,{payoutCents:3000,refundCents:2500})).ok,false);
 assert.equal((await decide(d)).ok,true);
 assert.equal((await d.approval.authorize(d.settlement)).ok,false);
 assert.equal((await finalize(d)).ok,false);
 assert.equal((await d.call(d.customer,"ack","Customer acknowledges")).ok,true);
 assert.equal((await d.call(d.owner,"ack","Owner acknowledges")).ok,true);
 assert.equal((await d.call(d.reviewer,"finalize","Same reviewer forbidden",{...d.amounts,evidenceDigest:d.digest})).ok,false);
 assert.equal((await finalize(d)).ok,true);
 assert.equal((await state(d.s)).status,"disputed");
 assert.equal((await d.confirm.dispatch({...d.settlement,kind:"payout"})).ok,false);
 await assert.rejects(disputePool.query("SELECT secret FROM securepay_private.dispute_actors"),e=>e.code==="42501");
});
test("appeal requires both parties' additional evidence; separate settlement and provider receipt enforce exact monetary split",async()=>{
 const d=await disputeFixture();
 assert.equal((await openCase(d)).ok,true);assert.equal((await evidence(d)).ok,true);assert.equal((await decide(d)).ok,true);
 assert.equal((await d.call(d.customer,"appeal","Customer challenges outcome",{evidenceDigest:d.digest})).ok,true);
 const revised={payoutCents:2000,refundCents:3000};
 assert.equal((await finalize(d,revised)).ok,false);
 assert.equal((await d.call(d.owner,"evidence","Owner appeal response",{evidenceDigest:d.digest})).ok,true);
 assert.equal((await finalize(d,revised)).ok,true);
 assert.equal((await d.approval.authorize(d.settlement)).ok,false);
 const settlement={...d.settlement,...revised};
 const forged=makeSettlementAuthorizer({pool:settlementPool,actorId:d.reviewer.actorId,key:d.reviewer.key});
 assert.equal((await forged.authorize(settlement)).ok,false);
 const auth=await Promise.all([d.approval.authorize(settlement),d.approval.authorize(settlement)]);
 assert.equal(auth.filter(x=>x.ok).length,1);
 const receipt=randomUUID();
 const dispatch=await Promise.all([d.confirm.dispatch({...settlement,kind:"payout"}),d.confirm.dispatch({...settlement,kind:"payout"})]);
 assert.equal(dispatch.filter(x=>x.ok).length,1);
 const payout=dispatch.find(x=>x.ok),refund=await d.confirm.dispatch({...settlement,kind:"refund"});assert.equal(refund.ok,true);
 const outcome={...settlement,...payout,outcome:"confirmed",receipt};
 // An ordinary release receipt must not be reused for a dispute settlement.
 const ordinary=await providerPayer({funded:true});
 const rr=await reserveProvider(ordinary);assert.equal(rr.ok,true);
 assert.equal((await provider.beginDispatch({...ordinary,requestId:rr.releaseRequestId})).ok,true);
 const usedReceipt=randomUUID();
 assert.equal((await providerEvent(ordinary,"released",{requestId:rr.releaseRequestId,transactionRef:usedReceipt})).status,"applied");
 assert.equal((await d.confirm.record({...outcome,receipt:usedReceipt})).ok,false);
 assert.equal((await d.confirm.record({...outcome,amountCents:1999})).ok,false);
 const fakeProvider=makeSettlementProvider({pool:providerPool,key:randomBytes(32)});
 assert.equal((await fakeProvider.record(outcome)).ok,false);
 const results=await Promise.all([d.confirm.record(outcome),d.confirm.record(outcome)]);
 assert.ok(results.every(x=>x.ok&&!x.moneyMoved));
 assert.equal((await state(d.s)).status,"disputed");
 assert.equal((await d.confirm.record({...settlement,...refund,outcome:"confirmed",receipt})).ok,false);
 assert.equal((await d.confirm.record({...settlement,...refund,outcome:"confirmed",receipt:randomUUID()})).ok,true);
 assert.equal((await d.confirm.dispatch({...settlement,kind:"payout"})).ok,false);
 assert.equal((await state(d.s)).status,"settled");
 const {rows:[r]}=await pool.query("SELECT status,payout_cents,refund_cents FROM securepay_private.dispute_settlements WHERE settlement_id=$1",[settlement.settlementId]);
 assert.deepEqual(r,{status:"confirmed",payout_cents:"2000",refund_cents:"3000"});
});
test("provider hold cannot be overridden by dispute finality; cross-tenant and replayed actions fail closed",async()=>{
 const d=await disputeFixture(),eventId=randomUUID();
 assert.equal((await d.call(d.customer,"open","serious",{evidenceDigest:d.digest,eventId,tenantId:randomUUID()})).ok,false);
 assert.equal((await d.call(d.customer,"open","serious",{evidenceDigest:d.digest,eventId})).ok,true);
 assert.equal((await d.call(d.customer,"open","serious",{evidenceDigest:d.digest,eventId})).ok,false);
 assert.equal((await evidence(d)).ok,true);assert.equal((await decide(d)).ok,true);
 assert.equal((await d.call(d.customer,"ack","Accepted")).ok,true);
 assert.equal((await d.call(d.owner,"ack","Accepted")).ok,true);
 assert.equal((await finalize(d)).ok,true);
 assert.equal((await providerEvent(d.s,"held")).status,"applied");
 assert.equal((await d.approval.authorize(d.settlement)).ok,false);
 assert.equal((await state(d.s)).status,"disputed");
});

function pngFixture(){
 const chunk=(type,data)=>{const name=Buffer.from(type),body=Buffer.concat([name,data]),size=Buffer.alloc(4),crc=Buffer.alloc(4);size.writeUInt32BE(data.length);crc.writeUInt32BE(crc32(body));return Buffer.concat([size,body,crc]);};
 const header=Buffer.alloc(13);header.writeUInt32BE(4,0);header.writeUInt32BE(4,4);header[8]=8;header[9]=2;
 const pixels=Buffer.concat(Array.from({length:4},()=>Buffer.concat([Buffer.from([0]),randomBytes(12)])));
 return Buffer.concat([Buffer.from("89504e470d0a1a0a","hex"),chunk("IHDR",header),chunk("IDAT",deflateSync(pixels)),chunk("IEND",Buffer.alloc(0))]);
}
const repair=(d,actor,action,extra={})=>actor.repairService.repair({...d.scope,action,details:"Documented repair action",...extra});
const photo=(d,actor,content=pngFixture())=>actor.repairService.storePhoto({...d.scope,mediaType:"image/png",content});
const repairState=async d=>(await pool.query("SELECT status,repair_phase,repair_photo_id,owner_responded_at,response_escalated_at FROM securepay_private.dispute_cases WHERE case_id=$1",[d.scope.caseId])).rows[0];
test("rectification requires agreed plan and fresh owner photo; accepted repairs require full payout but never release automatically",async()=>{
 const d=await disputeFixture();assert.equal((await openCase(d)).ok,true);
 const before=await photo(d,d.owner);assert.equal(before.ok,true);
 const dueEpoch=Math.floor(Date.now()/1000)+86400;
 assert.equal((await repair(d,d.owner,"propose",{dueEpoch})).ok,true);
 assert.equal((await repair(d,d.owner,"accept_plan")).ok,false);
 assert.equal((await evidence(d)).ok,true);
 assert.equal((await decide(d)).ok,false);
 assert.equal((await repair(d,d.customer,"accept_plan")).ok,true);
 assert.equal((await repair(d,d.owner,"submit_repair",{photoId:before.photoId})).ok,false);
 const p=await photo(d,d.owner);assert.equal(p.ok,true);
 const other=await photo(d,d.customer);assert.equal(other.ok,true);
 assert.equal((await repair(d,d.owner,"submit_repair",{photoId:other.photoId})).ok,false);
 assert.equal((await repair(d,d.owner,"submit_repair",{photoId:p.photoId})).ok,true);
 assert.equal((await repair(d,d.customer,"accept_repair",{photoId:other.photoId})).ok,false);
 assert.equal((await repair(d,d.customer,"accept_repair",{photoId:p.photoId})).ok,true);
 assert.equal((await repairState(d)).repair_phase,"accepted");
 assert.equal((await decide(d)).ok,false);
 assert.equal((await decide(d,{payoutCents:5000,refundCents:0})).ok,true);
 assert.equal((await state(d.s)).status,"disputed");
 assert.equal((await d.approval.authorize({...d.settlement,payoutCents:5000,refundCents:0})).ok,false);
});
test("photo bytes are hash-bound, bounded and readable only by case parties or assigned reviewers",async()=>{
 const d=await disputeFixture(),other=await disputeFixture();assert.equal((await openCase(d)).ok,true);assert.equal((await openCase(other)).ok,true);
 const content=pngFixture(),p=await photo(d,d.owner,content);assert.equal(p.ok,true);
 assert.equal((await photo(d,d.owner,content)).ok,false);
 assert.equal((await photo(d,d.owner,Buffer.from("invalid image"))).ok,false);
 await assert.rejects(photo(d,d.owner,Buffer.alloc(2097153)),/Invalid evidence/);
 const query={...d.scope,photoId:p.photoId};
 assert.deepEqual((await d.customer.repairService.readPhoto(query)).content,content);
 assert.equal(await d.reviewer.repairService.readPhoto(query),null);
 assert.equal(await other.customer.repairService.readPhoto(query),null);
 await pool.query("INSERT INTO securepay_private.dispute_photo_reviewers(case_id,tenant_id,reviewer_id) VALUES($1,$2,$3)",[d.scope.caseId,d.scope.tenantId,d.reviewer.actorId]);
 assert.equal((await d.reviewer.repairService.readPhoto(query)).digest,p.digest);
 await assert.rejects(disputePool.query("SELECT content FROM securepay_private.dispute_photos"),e=>e.code==="42501");
 await assert.rejects(disputePool.query("UPDATE securepay_private.dispute_photos SET content=$1",[content]),e=>e.code==="42501");
});
test("business deadlines exclude weekends and configured holidays; overdue actions escalate without payout",async()=>{
 const due=async n=>(await pool.query("SELECT securepay_private.business_deadline($1,$2) AS due",["2026-11-20T00:00:00Z",n])).rows[0].due.toISOString();
 assert.equal(await due(1),"2026-11-23T06:00:00.000Z");
 assert.equal(await due(2),"2026-11-24T06:00:00.000Z");
 await pool.query("INSERT INTO securepay_private.dispute_holidays VALUES ('2026-11-23')");
 try{assert.equal(await due(2),"2026-11-25T06:00:00.000Z");}finally{await pool.query("DELETE FROM securepay_private.dispute_holidays WHERE day='2026-11-23'");}
 const d=await disputeFixture();
 assert.equal((await d.call(d.customer,"open","serious",{evidenceDigest:d.digest})).ok,true);
 const dueEpoch=Math.floor(Date.now()/1000)+86400;
 assert.equal((await repair(d,d.owner,"propose",{dueEpoch})).ok,false);
 assert.equal((await repair(d,d.reviewer,"reviewer_plan",{dueEpoch})).ok,true);
 await pool.query("UPDATE securepay_private.dispute_cases SET response_due_at=clock_timestamp()-interval '1 second',repair_due_at=clock_timestamp()-interval '1 second' WHERE case_id=$1",[d.scope.caseId]);
 const checks=await Promise.all([scanDisputeDeadlines(escalationPool),scanDisputeDeadlines(escalationPool)]);
 assert.equal(checks[0]+checks[1],1);
 const row=await repairState(d);assert.equal(row.repair_phase,"escalated");assert.ok(row.response_escalated_at);assert.equal(row.status,"open");
 const events=await pool.query("SELECT kind FROM securepay_private.dispute_deadline_events WHERE case_id=$1 ORDER BY kind",[d.scope.caseId]);
 assert.deepEqual(events.rows.map(r=>r.kind),["owner_response_overdue","repair_overdue"]);
 assert.equal(await scanDisputeDeadlines(escalationPool),0);
 assert.equal((await state(d.s)).status,"disputed");
 assert.equal((await d.approval.authorize(d.settlement)).ok,false);
 assert.equal((await evidence(d)).ok,true);assert.ok((await repairState(d)).owner_responded_at);
 assert.equal((await decide(d)).ok,true);
 await assert.rejects(escalationPool.query("SELECT * FROM securepay_private.dispute_cases"),e=>e.code==="42501");
});

test("encrypted evidence rotates write keys without altering prior content; corruption and missing keys fail closed",async()=>{
 const d=await disputeFixture();assert.equal((await openCase(d)).ok,true);
 const bytes=pngFixture(),p=await photo(d,d.owner,bytes);assert.equal(p.ok,true);
 const load=async id=>(await pool.query("SELECT content,key_id,plaintext_size FROM securepay_private.dispute_photos WHERE photo_id=$1",[id])).rows[0];
 const stored=await load(p.photoId);assert.notDeepEqual(stored.content,bytes);assert.equal(stored.plaintext_size,bytes.length);assert.equal(stored.key_id,"primary");
 const read=()=>d.customer.repairService.readPhoto({...d.scope,photoId:p.photoId});
 await assert.rejects(disputePool.query("SELECT secret FROM securepay_private.evidence_keys"),e=>e.code==="42501");
 try{
  await pool.query("UPDATE securepay_private.evidence_keys SET write_enabled=false WHERE key_id='primary'");
  assert.equal((await photo(d,d.owner)).ok,false);
  await pool.query("INSERT INTO securepay_private.evidence_keys(key_id,secret,write_enabled) VALUES('rotation-test',$1,true)",[randomBytes(32)]);
  const newer=await photo(d,d.owner);assert.equal(newer.ok,true);
  assert.equal((await load(newer.photoId)).key_id,"rotation-test");
  assert.deepEqual((await read()).content,bytes);
  await pool.query("UPDATE securepay_private.evidence_keys SET read_enabled=false WHERE key_id='primary'");
  await assert.rejects(read(),/Evidence unavailable/);
  await pool.query("UPDATE securepay_private.evidence_keys SET read_enabled=true WHERE key_id='primary'");
  const corrupt=Buffer.from(stored.content);corrupt[corrupt.length-10]^=1;
  await pool.query("UPDATE securepay_private.dispute_photos SET content=$2 WHERE photo_id=$1",[p.photoId,corrupt]);
  await assert.rejects(read());
  await pool.query("UPDATE securepay_private.dispute_photos SET content=$2 WHERE photo_id=$1",[p.photoId,stored.content]);
  assert.deepEqual((await read()).content,bytes);
 }finally{
  await pool.query("UPDATE securepay_private.evidence_keys SET write_enabled=false WHERE key_id='rotation-test'; UPDATE securepay_private.evidence_keys SET write_enabled=true,read_enabled=true WHERE key_id='primary'");
 }
});
test("tenant audit export verifies paged chain, subsequent checkpoint continuity and evidence access",async()=>{
 const d=await disputeFixture();assert.equal((await openCase(d)).ok,true);
 const first=await verifyAuditChain(auditPool,d.s.tenantId,{pageSize:2});assert.equal(first.ok,true);assert.ok(BigInt(first.checkpoint.last_seq)>0n);
 const p=await photo(d,d.owner);assert.equal(p.ok,true);
 assert.ok(await d.customer.repairService.readPhoto({...d.scope,photoId:p.photoId}));
 const next=await verifyAuditChain(auditPool,d.s.tenantId,{checkpoint:first.checkpoint,pageSize:2});assert.equal(next.ok,true);
 assert.ok(BigInt(next.checkpoint.last_seq)>BigInt(first.checkpoint.last_seq));
 const {rows}=await pool.query("SELECT operation,source FROM securepay_private.audit_chain WHERE tenant_id=$1 ORDER BY seq",[d.s.tenantId]);
 assert.ok(rows.some(r=>r.source==="dispute_photos"&&r.operation==="READ"));
 assert.ok(rows.some(r=>r.source==="provider_events"));
 assert.ok(rows.some(r=>r.source==="audit_events"));
 await assert.rejects(disputePool.query("SELECT * FROM securepay_private.audit_chain"),e=>e.code==="42501");
 await assert.rejects(auditPool.query("UPDATE securepay_private.audit_chain SET row_digest=$1",["0".repeat(64)]),e=>e.code==="42501");
 const empty=await verifyAuditChain(auditPool,randomUUID());assert.equal(empty.checkpoint.last_seq,"0");
});
test("independent verifier detects altered rows, deleted entries and rewritten head against retained checkpoint",async()=>{
 const d=await disputeFixture();assert.equal((await openCase(d)).ok,true);
 const t=d.s.tenantId,original=await verifyAuditChain(auditPool,t);assert.equal(original.ok,true);
 const saved=(await pool.query("SELECT * FROM securepay_private.audit_chain WHERE tenant_id=$1 AND seq=1",[t])).rows[0];
 await pool.query("UPDATE securepay_private.audit_chain SET row_digest=$2 WHERE tenant_id=$1 AND seq=1",[t,"0".repeat(64)]);
 assert.equal((await verifyAuditChain(auditPool,t)).ok,false);
 await pool.query("UPDATE securepay_private.audit_chain SET row_digest=$2 WHERE tenant_id=$1 AND seq=1",[t,saved.row_digest]);
 assert.equal((await verifyAuditChain(auditPool,t)).ok,true);
 await pool.query("DELETE FROM securepay_private.audit_chain WHERE tenant_id=$1 AND seq=1",[t]);
 assert.equal((await verifyAuditChain(auditPool,t)).ok,false);
 await pool.query("INSERT INTO securepay_private.audit_chain(tenant_id,seq,source,operation,row_digest,occurred_us,prev_hash,entry_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)",[t,saved.seq,saved.source,saved.operation,saved.row_digest,saved.occurred_us,saved.prev_hash,saved.entry_hash]);
 assert.equal((await verifyAuditChain(auditPool,t)).ok,true);
 const prior=(await pool.query("SELECT entry_hash,seq FROM securepay_private.audit_chain WHERE tenant_id=$1 ORDER BY seq DESC OFFSET 1 LIMIT 1",[t])).rows[0];
 await pool.query("DELETE FROM securepay_private.audit_chain WHERE tenant_id=$1 AND seq>$2",[t,prior.seq]);
 await pool.query("UPDATE securepay_private.audit_chain_heads SET last_seq=$2,last_hash=$3 WHERE tenant_id=$1",[t,prior.seq,prior.entry_hash]);
 assert.equal((await verifyAuditChain(auditPool,t)).ok,true);
 assert.deepEqual(await verifyAuditChain(auditPool,t,{checkpoint:original.checkpoint}),{ok:false,reason:"truncated_history"});
});

test("strict evidence validation rejects malformed, oversized, trailing and unscreened bytes; scanner failures deny storage",async()=>{
 const d=await disputeFixture();assert.equal((await openCase(d)).ok,true);
 const content=pngFixture();assert.equal(validEvidencePNG(content),true);
 assert.equal(validEvidencePNG(Buffer.concat([content,Buffer.from("trailing")])),false);
 assert.equal(validEvidencePNG(content.subarray(0,-1)),false);
 const corrupted=Buffer.from(content);corrupted[corrupted.length-1]^=1;assert.equal(validEvidencePNG(corrupted),false);
 assert.equal(validEvidencePNG(Buffer.alloc(2097153)),false);
 const scope={...d.scope,mediaType:"image/png",content};
 for(const result of ["infected","unavailable",undefined]){
  const actor=makeRectificationActor({pool:disputePool,actorId:d.owner.actorId,key:d.owner.key,scanner:makeEvidenceScanner({key:scanKey,scan:async()=>result})});
  assert.equal((await actor.storePhoto(scope)).ok,false);
 }
 const fake=makeRectificationActor({pool:disputePool,actorId:d.owner.actorId,key:d.owner.key,scanner:makeEvidenceScanner({key:randomBytes(32),scan:async()=>"clean"})});
 assert.equal((await fake.storePhoto(scope)).ok,false);
 const bypass=makeRectificationActor({pool:disputePool,actorId:d.owner.actorId,key:d.owner.key});
 assert.equal((await bypass.storePhoto(scope)).ok,false);
 await assert.rejects(disputePool.query("SELECT securepay_private.store_dispute_photo(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)"),e=>e.code==="42501");
 const p=await d.owner.repairService.storePhoto(scope);assert.equal(p.ok,true);
 const r=(await pool.query("SELECT scan_key_id,screened_at FROM securepay_private.dispute_photos WHERE photo_id=$1",[p.photoId])).rows[0];
 assert.equal(r.scan_key_id,"primary");assert.ok(r.screened_at);
});
test("scanner attestation is bound to exact content and scope, with revoked or expired key rejection",async()=>{
 const d=await disputeFixture();assert.equal((await openCase(d)).ok,true);
 const photoId=randomUUID(),content=pngFixture(),scope={...d.scope,photoId,mediaType:"image/png",content};
 const proof=await scanner.attest({...scope,actorId:d.owner.actorId});assert.ok(proof);
 const stale=makeRectificationActor({pool:disputePool,actorId:d.owner.actorId,key:d.owner.key,scanner:{attest:async()=>proof}});
 assert.equal((await stale.storePhoto({...scope,photoId:randomUUID()})).ok,false);
 assert.equal((await stale.storePhoto({...scope,content:pngFixture()})).ok,false);
 await pool.query("UPDATE securepay_private.evidence_scan_keys SET active=false WHERE key_id='primary'");
 try{assert.equal((await stale.storePhoto(scope)).ok,false);}finally{await pool.query("UPDATE securepay_private.evidence_scan_keys SET active=true WHERE key_id='primary'");}
 await pool.query("UPDATE securepay_private.evidence_scan_keys SET valid_until=clock_timestamp()-interval '1 second' WHERE key_id='primary'");
 try{assert.equal((await stale.storePhoto(scope)).ok,false);}finally{await pool.query("UPDATE securepay_private.evidence_scan_keys SET valid_until=NULL WHERE key_id='primary'");}
 assert.equal((await stale.storePhoto(scope)).ok,true);
 assert.equal((await stale.storePhoto(scope)).ok,false);
});
test("evidence retention requires explicit expired policy, settled case and lifted hold; purge preserves audit and tombstone",async()=>{
 const d=await disputeFixture();assert.equal((await openCase(d)).ok,true);
 const p=await photo(d,d.owner);assert.equal(p.ok,true);
 assert.equal(await purgeExpiredEvidence(retentionPool),0);
 await pool.query("INSERT INTO securepay_private.evidence_retention_policy(case_id,tenant_id,retain_until,legal_hold,reason) VALUES($1,$2,clock_timestamp()-interval '1 day',false,'Synthetic approved retention test')",[d.scope.caseId,d.scope.tenantId]);
 assert.equal(await purgeExpiredEvidence(retentionPool),0);
 assert.equal((await evidence(d)).ok,true);assert.equal((await decide(d)).ok,true);
 assert.equal((await d.call(d.customer,"ack","Accepted")).ok,true);assert.equal((await d.call(d.owner,"ack","Accepted")).ok,true);
 assert.equal((await finalize(d)).ok,true);assert.equal((await d.approval.authorize(d.settlement)).ok,true);
 await finishSettlement(d);
 await pool.query("UPDATE securepay_private.evidence_retention_policy SET legal_hold=true WHERE case_id=$1",[d.scope.caseId]);
 assert.equal(await purgeExpiredEvidence(retentionPool),0);
 await pool.query("UPDATE securepay_private.evidence_retention_policy SET legal_hold=false,retain_until=clock_timestamp()+interval '1 day' WHERE case_id=$1",[d.scope.caseId]);
 assert.equal(await purgeExpiredEvidence(retentionPool),0);
 await pool.query("UPDATE securepay_private.evidence_retention_policy SET retain_until=clock_timestamp()-interval '1 second' WHERE case_id=$1",[d.scope.caseId]);
 const runs=await Promise.all([purgeExpiredEvidence(retentionPool),purgeExpiredEvidence(retentionPool)]);assert.equal(runs[0]+runs[1],1);
 assert.equal(await d.customer.repairService.readPhoto({...d.scope,photoId:p.photoId}),null);
 const r=(await pool.query("SELECT content,digest,purged_at FROM securepay_private.dispute_photos WHERE photo_id=$1",[p.photoId])).rows[0];
 assert.equal(r.content,null);assert.equal(r.digest,p.digest);assert.ok(r.purged_at);
 assert.equal((await verifyAuditChain(auditPool,d.scope.tenantId)).ok,true);
 await assert.rejects(retentionPool.query("SELECT * FROM securepay_private.dispute_photos"),e=>e.code==="42501");
 await assert.rejects(disputePool.query("UPDATE securepay_private.evidence_retention_policy SET legal_hold=false"),e=>e.code==="42501");
});

test("normalized JPEG provenance is bound to original bytes and stored derivative",async()=>{
 const d=await disputeFixture();assert.equal((await openCase(d)).ok,true);
 // The real JPEG decoder is exercised separately against Pillow in CI.
 const input=Buffer.from("ffd8ffe000104a4649460001010000010001ffd9","hex"),normalized=pngFixture(),scans=[];
 const jpegScanner=makeEvidenceScanner({key:scanKey,scan:async bytes=>{scans.push(Buffer.from(bytes));return "clean";},normalizeJPEG:async()=>normalized});
 const actor=makeRectificationActor({pool:disputePool,actorId:d.owner.actorId,key:d.owner.key,scanner:jpegScanner});
 const scope={...d.scope,mediaType:"image/jpeg",content:input};
 const p=await actor.storePhoto(scope);assert.equal(p.ok,true);
 assert.deepEqual(scans,[input,normalized]);
 const {rows:[r]}=await pool.query("SELECT media_type,digest,original_media_type,original_digest FROM securepay_private.dispute_photos WHERE photo_id=$1",[p.photoId]);
 assert.deepEqual(r,{media_type:"image/png",digest:createHash("sha256").update(normalized).digest("hex"),original_media_type:"image/jpeg",original_digest:createHash("sha256").update(input).digest("hex")});
 assert.deepEqual((await d.customer.repairService.readPhoto({...d.scope,photoId:p.photoId})).content,normalized);
 const reject=makeRectificationActor({pool:disputePool,actorId:d.owner.actorId,key:d.owner.key,scanner:makeEvidenceScanner({key:scanKey,scan:async bytes=>bytes.equals(normalized)?"infected":"clean",normalizeJPEG:async()=>normalized})});
 assert.equal((await reject.storePhoto(scope)).ok,false);
 await assert.rejects(disputePool.query("SELECT securepay_private.store_screened_photo(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)"),e=>e.code==="42501");
});
test("independent authority instances share a bounded authenticated account and global request budget",async()=>{
 const key=randomBytes(32),issuer="https://sandbox-issuer.invalid",identity={subject:randomUUID()};
 const a=makeSharedCustomerBudget({pool:payerPool,key,issuer}),b=makeSharedCustomerBudget({pool:payerPool,key,issuer});
 const reset=()=>pool.query("UPDATE securepay_private.abuse_global SET window_id=0,used=0");
 // A clock rollover is possible during CI. Repeat a boundary-crossing sample only.
 let results;
 for(let repeat=0;repeat<3;repeat++){
  await reset();
  const start=(await pool.query("SELECT floor(extract(epoch FROM clock_timestamp())/60)::bigint AS w")).rows[0].w;
  results=await Promise.all(Array.from({length:24},(_,i)=>(i%2?a:b)(identity)));
  const end=(await pool.query("SELECT floor(extract(epoch FROM clock_timestamp())/60)::bigint AS w")).rows[0].w;
  if(start===end)break;
  results=null;
 }
 assert.ok(results);assert.equal(results.filter(Boolean).length,20);
 assert.equal((await pool.query("SELECT count(*)::int AS n FROM securepay_private.abuse_buckets")).rows[0].n,1);
 assert.equal(await a({subject:""}),false);
 // Controlled near-cap fixture demonstrates atomic global admission.
 let globalResults;
 for(let repeat=0;repeat<3;repeat++){
  await pool.query("UPDATE securepay_private.abuse_global SET used=599,window_id=floor(extract(epoch FROM clock_timestamp())/60)::bigint");
  const start=(await pool.query("SELECT window_id AS w FROM securepay_private.abuse_global")).rows[0].w;
  globalResults=await Promise.all([a({subject:randomUUID()}),b({subject:randomUUID()})]);
  const end=(await pool.query("SELECT window_id AS w FROM securepay_private.abuse_global")).rows[0].w;
  if(start===end)break;
  globalResults=null;
 }
 assert.ok(globalResults);assert.equal(globalResults.filter(Boolean).length,1);
 await reset();assert.equal(await a(identity),true);
 await assert.rejects(payerPool.query("SELECT * FROM securepay_private.abuse_buckets"),e=>e.code==="42501");
 await assert.rejects(disputePool.query("SELECT securepay_private.take_customer_budget($1)",["a".repeat(64)]),e=>e.code==="42501");
});

async function authorizedDispute(amounts){
 const d=await disputeFixture(); const split=amounts??d.amounts;
 assert.equal((await openCase(d)).ok,true);assert.equal((await evidence(d)).ok,true);assert.equal((await decide(d,split)).ok,true);
 assert.equal((await d.call(d.customer,"ack","Accepted")).ok,true);assert.equal((await d.call(d.owner,"ack","Accepted")).ok,true);
 assert.equal((await finalize(d,split)).ok,true);d.settlement={...d.settlement,...split};
 assert.equal((await d.approval.authorize(d.settlement)).ok,true);return d;
}
async function finishSettlement(d){
 for(const kind of ["payout","refund"]){
  const amount=d.settlement[kind+"Cents"];if(amount===0)continue;
  const leg=await d.confirm.dispatch({...d.settlement,kind});assert.equal(leg.ok,true);
  assert.equal((await d.confirm.record({...d.settlement,...leg,outcome:"confirmed",receipt:randomUUID()})).ok,true);
 }
}
test("partial settlement failure freezes completion; independently authorized retry reuses the same refund key and never repeats successful payout",async()=>{
 const d=await authorizedDispute(),scope=d.settlement;
 const payout=await d.confirm.dispatch({...scope,kind:"payout"});assert.equal(payout.ok,true);
 const payoutReceipt=randomUUID();
 assert.equal((await d.confirm.record({...scope,...payout,outcome:"confirmed",receipt:payoutReceipt})).status,"applied");
 const refund=await d.confirm.dispatch({...scope,kind:"refund"});assert.equal(refund.ok,true);
 assert.equal((await d.confirm.record({...scope,...refund,outcome:"unknown"})).status,"applied");
 assert.equal((await d.approval.retry({...scope,...refund})).ok,false);
 assert.equal((await d.confirm.dispatch({...scope,kind:"refund"})).ok,false);
 assert.equal((await state(d.s)).status,"disputed");
 assert.equal((await d.confirm.record({...scope,...refund,outcome:"not_executed"})).status,"applied");
 const rogue=makeSettlementAuthorizer({pool:settlementPool,actorId:d.reviewer.actorId,key:d.reviewer.key});
 assert.equal((await rogue.retry({...scope,...refund})).ok,false);
 const retry=await Promise.all([d.approval.retry({...scope,...refund}),d.approval.retry({...scope,...refund})]);
 assert.equal(retry.filter(x=>x.ok).length,1);
 const again=await d.confirm.dispatch({...scope,kind:"refund"});assert.equal(again.ok,true);
 assert.equal(again.idempotencyKey,refund.idempotencyKey);assert.equal(again.attempt,2);
 assert.equal((await d.confirm.dispatch({...scope,kind:"payout"})).ok,false);
 assert.equal((await d.confirm.record({...scope,...again,outcome:"confirmed",receipt:payoutReceipt})).ok,false);
 const receipt=randomUUID(),eventId=randomUUID();
 const result=await Promise.all([d.confirm.record({...scope,...again,outcome:"confirmed",receipt,eventId}),d.confirm.record({...scope,...again,outcome:"confirmed",receipt,eventId})]);
 assert.deepEqual(result.map(x=>x.status).sort(),["applied","duplicate"]);
 assert.equal((await state(d.s)).status,"settled");
 assert.equal((await verifyAuditChain(auditPool,d.s.tenantId)).ok,true);
});
test("contradictory signed receipt freezes undispatched remainder and leaves durable reconciliation evidence",async()=>{
 const d=await authorizedDispute(),scope=d.settlement;
 const payout=await d.confirm.dispatch({...scope,kind:"payout"});
 assert.equal((await d.confirm.record({...scope,...payout,outcome:"not_executed"})).status,"applied");
 assert.equal((await d.approval.retry({...scope,...payout})).ok,true);
 assert.equal((await d.confirm.record({...scope,...payout,outcome:"confirmed",receipt:randomUUID()})).status,"reconcile");
 assert.equal((await d.confirm.dispatch({...scope,kind:"payout"})).ok,false);
 assert.equal((await d.confirm.dispatch({...scope,kind:"refund"})).ok,false);
 const rows=await pool.query("SELECT reason FROM securepay_private.settlement_leg_conflicts WHERE case_id=$1",[scope.caseId]);
 assert.deepEqual(rows.rows,[{reason:"contradictory_receipt"}]);
 assert.equal((await state(d.s)).status,"disputed");
});
test("full refund omits zero payout; legacy aggregate endpoints and direct leg mutation are denied",async()=>{
 const d=await authorizedDispute({payoutCents:0,refundCents:5000}),scope=d.settlement;
 assert.equal((await d.confirm.dispatch({...scope,kind:"payout"})).ok,false);
 await assert.rejects(providerPool.query("SELECT securepay_private.begin_settlement_dispatch($1,$2,$3,$4)",[scope.settlementId,scope.tenantId,scope.milestoneId,scope.caseId]),e=>e.code==="42501");
 await assert.rejects(providerPool.query("SELECT securepay_private.confirm_settlement(NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL)"),e=>e.code==="42501");
 await assert.rejects(providerPool.query("UPDATE securepay_private.settlement_legs SET status='confirmed'"),e=>e.code==="42501");
 await finishSettlement(d);assert.equal((await state(d.s)).status,"settled");
 const rows=await pool.query("SELECT kind,amount_cents,status FROM securepay_private.settlement_legs WHERE settlement_id=$1",[scope.settlementId]);
 assert.deepEqual(rows.rows,[{kind:"refund",amount_cents:"5000",status:"confirmed"}]);
});

test("late provider hold preserves already-dispatched receipt and blocks outstanding leg",async()=>{
 const d=await authorizedDispute(),scope=d.settlement;
 const payout=await d.confirm.dispatch({...scope,kind:"payout"});assert.equal(payout.ok,true);
 assert.equal((await d.confirm.record({...scope,...payout,outcome:"unknown"})).status,"applied");
 assert.equal((await providerEvent(d.s,"held")).status,"applied");
 assert.equal((await d.confirm.record({...scope,...payout,outcome:"confirmed",receipt:randomUUID()})).status,"applied");
 assert.equal((await d.confirm.dispatch({...scope,kind:"refund"})).ok,false);
 assert.equal((await state(d.s)).status,"disputed");
 const r=await pool.query("SELECT reason FROM securepay_private.provider_reconciliation WHERE tenant_id=$1 AND milestone_id=$2",[scope.tenantId,scope.milestoneId]);
 assert.deepEqual(r.rows,[{reason:"hold_after_dispatch"}]);
});

async function reconciler(d){
 const actorId=randomUUID(),key=randomBytes(32);
 await pool.query("INSERT INTO securepay_private.dispute_actors(tenant_id,actor_id,role,secret) VALUES($1,$2,'reconciler',$3)",[d.scope.tenantId,actorId,key]);
 return {actorId,key};
}
async function recoveryFixture(d,extra){
 const one=await reconciler(d),two=await reconciler(d);
 const packet=await prepareRecovery(reconciliationPool,{...d.settlement,...extra,actorOne:one.actorId,actorTwo:two.actorId,
 evidenceDigest:randomBytes(32).toString("hex"),reason:"Independent synthetic provider statement reconciliation"});
 const providerSig=signProviderRecovery(packet,providerKey),sig1=signReviewerRecovery(packet,one.actorId,one.key),sig2=signReviewerRecovery(packet,two.actorId,two.key);
 return {packet,one,two,providerSig,sig1,sig2,apply:()=>applyRecovery(reconciliationPool,packet,providerSig,sig1,sig2)};
}
const balanceFor=async s=>(await auditPool.query("SELECT * FROM securepay_private.financial_balance($1,$2)",[s.tenantId,s.milestoneId])).rows[0];
test("financial journal reconciles exact funding and individual receipts, no duplicate entries or direct runtime mutation",async()=>{
 const d=await authorizedDispute();
 assert.deepEqual(await balanceFor(d.s),{funded_cents:"5000",payout_cents:"0",refund_cents:"0",remaining_cents:"5000"});
 const payout=await d.confirm.dispatch({...d.settlement,kind:"payout"}),receipt=randomUUID();
 const event={...d.settlement,...payout,outcome:"confirmed",receipt};
 assert.equal((await d.confirm.record(event)).status,"applied");
 assert.equal((await d.confirm.record(event)).status,"duplicate");
 assert.deepEqual(await balanceFor(d.s),{funded_cents:"5000",payout_cents:"3000",refund_cents:"0",remaining_cents:"2000"});
 const refund=await d.confirm.dispatch({...d.settlement,kind:"refund"});
 assert.equal((await d.confirm.record({...d.settlement,...refund,outcome:"confirmed",receipt:randomUUID()})).ok,true);
 assert.deepEqual(await balanceFor(d.s),{funded_cents:"5000",payout_cents:"3000",refund_cents:"2000",remaining_cents:"0"});
 assert.equal((await state(d.s)).status,"settled");
 await assert.rejects(providerPool.query("DELETE FROM securepay_private.financial_journal"),e=>e.code==="42501");
 const ordinary=await providerPayer({funded:true}),r=await reserveProvider(ordinary);
 assert.equal((await provider.beginDispatch({...ordinary,requestId:r.releaseRequestId})).ok,true);
 assert.equal((await providerEvent(ordinary,"released",{requestId:r.releaseRequestId,transactionRef:randomUUID()})).status,"applied");
 assert.deepEqual(await balanceFor(ordinary),{funded_cents:"5000",payout_cents:"5000",refund_cents:"0",remaining_cents:"0"});
 const verify=async s=>(await auditPool.query("SELECT securepay_private.verify_financial_journal($1,$2) AS ok",[s.tenantId,s.milestoneId])).rows[0].ok;
 assert.equal(await verify(ordinary),true);assert.equal(await verify(d.s),true);
 await pool.query("UPDATE securepay_private.financial_journal SET amount_cents=amount_cents-1 WHERE tenant_id=$1 AND milestone_id=$2 AND kind='settlement_refund'",[d.s.tenantId,d.s.milestoneId]);
 assert.equal(await verify(d.s),false);assert.equal(await verify(ordinary),true);
 await pool.query("UPDATE securepay_private.financial_journal SET amount_cents=amount_cents+1 WHERE tenant_id=$1 AND milestone_id=$2 AND kind='settlement_refund'",[d.s.tenantId,d.s.milestoneId]);
 assert.equal(await verify(d.s),true);
});
test("exhausted leg requires current provider statement and distinct independent approvals for one final retry",async()=>{
 const d=await authorizedDispute({payoutCents:0,refundCents:5000});
 let leg;
 for(let attempt=1;attempt<=3;attempt++){
  leg=await d.confirm.dispatch({...d.settlement,kind:"refund"});assert.equal(leg.attempt,attempt);
  assert.equal((await d.confirm.record({...d.settlement,...leg,outcome:"not_executed"})).status,"applied");
  if(attempt<3)assert.equal((await d.approval.retry({...d.settlement,...leg})).ok,true);
 }
 const rec=await recoveryFixture(d,{legId:leg.legId,action:"retry_once"});
 assert.equal((await applyRecovery(reconciliationPool,rec.packet,rec.providerSig,rec.sig1,rec.sig1)).ok,false);
 assert.equal((await applyRecovery(reconciliationPool,rec.packet,signProviderRecovery(rec.packet,randomBytes(32)),rec.sig1,rec.sig2)).ok,false);
 const results=await Promise.all([rec.apply(),rec.apply()]);assert.equal(results.filter(x=>x.ok).length,1);
 const last=await d.confirm.dispatch({...d.settlement,kind:"refund"});assert.equal(last.attempt,4);assert.equal(last.legId,leg.legId);
 assert.equal((await d.confirm.record({...d.settlement,...last,outcome:"not_executed"})).ok,true);
 const exhausted=await recoveryFixture(d,{legId:leg.legId,action:"retry_once"});assert.equal((await exhausted.apply()).ok,false);
 assert.equal((await d.confirm.dispatch({...d.settlement,kind:"refund"})).ok,false);
 assert.equal((await state(d.s)).status,"disputed");assert.equal((await balanceFor(d.s)).remaining_cents,"5000");
});
test("dual recovery accepts exclusively quarantined receipt, rejects stale state and balances the settlement",async()=>{
 const d=await authorizedDispute({payoutCents:0,refundCents:5000});
 const leg=await d.confirm.dispatch({...d.settlement,kind:"refund"});
 assert.equal((await d.confirm.record({...d.settlement,...leg,outcome:"not_executed"})).ok,true);
 const receipt=randomUUID(),stale=await recoveryFixture(d,{legId:leg.legId,action:"confirm",receipt});
 assert.equal((await d.confirm.record({...d.settlement,...leg,outcome:"confirmed",receipt})).status,"reconcile");
 assert.equal((await stale.apply()).ok,false);
 const rec=await recoveryFixture(d,{legId:leg.legId,action:"confirm",receipt});
 assert.equal((await rec.apply()).ok,true);assert.equal((await rec.apply()).ok,false);
 assert.equal((await state(d.s)).status,"settled");assert.equal((await balanceFor(d.s)).remaining_cents,"0");
 const r=(await pool.query("SELECT resolved_at,resolution_id FROM securepay_private.settlement_leg_conflicts WHERE case_id=$1",[d.scope.caseId])).rows[0];
 assert.ok(r.resolved_at);assert.equal(r.resolution_id,rec.packet.resolutionId);
 assert.equal((await verifyAuditChain(auditPool,d.s.tenantId)).ok,true);
});
test("signed dual hold recovery cannot dispatch during uncertainty and lifts only the matching provider hold",async()=>{
 const d=await authorizedDispute(),leg=await d.confirm.dispatch({...d.settlement,kind:"payout"});
 assert.equal((await providerEvent(d.s,"held")).status,"applied");
 const premature=await recoveryFixture(d,{action:"lift_hold"});assert.equal((await premature.apply()).ok,false);
 assert.equal((await d.confirm.record({...d.settlement,...leg,outcome:"confirmed",receipt:randomUUID()})).ok,true);
 const rec=await recoveryFixture(d,{action:"lift_hold"});assert.equal((await rec.apply()).ok,true);
 const refund=await d.confirm.dispatch({...d.settlement,kind:"refund"});assert.equal(refund.ok,true);
 assert.equal((await d.confirm.record({...d.settlement,...refund,outcome:"confirmed",receipt:randomUUID()})).ok,true);
 assert.equal((await state(d.s)).status,"settled");assert.equal((await balanceFor(d.s)).remaining_cents,"0");
 const hold=(await pool.query("SELECT resolved_at FROM securepay_private.provider_reconciliation WHERE tenant_id=$1 AND milestone_id=$2",[d.scope.tenantId,d.scope.milestoneId])).rows[0];assert.ok(hold.resolved_at);
});

async function reportingActor(tenantId){
 const actorId=randomUUID(),key=randomBytes(32);
 await pool.query("INSERT INTO securepay_private.reporting_actors(tenant_id,actor_id,secret) VALUES($1,$2,$3)",[tenantId,actorId,key]);
 return {tenantId,actorId,key};
}
test("tenant-scoped reconciliation snapshot exposes exact balances and no other tenant or sensitive records",async()=>{
 const d=await authorizedDispute(),other=await authorizedDispute();
 const payout=await d.confirm.dispatch({...d.settlement,kind:"payout"});
 assert.equal((await d.confirm.record({...d.settlement,...payout,outcome:"confirmed",receipt:randomUUID()})).ok,true);
 const refund=await d.confirm.dispatch({...d.settlement,kind:"refund"});
 assert.equal((await d.confirm.record({...d.settlement,...refund,outcome:"unknown"})).ok,true);
 const actor=await reportingActor(d.s.tenantId);
 const report=await loadReconciliationReport(reportingPool,actor);
 assert.equal(report.milestones.length,1);
 assert.equal(report.milestones[0].milestoneId,d.s.milestoneId);
 assert.deepEqual(summarizeReport(report),{fundedCents:"5000",payoutCents:"3000",refundCents:"0",remainingCents:"2000",unresolvedIssues:"0",milestoneCount:1,mismatches:0,uncertainLegs:1,disputedMilestones:1});
 assert.equal(JSON.stringify(report).includes(other.s.milestoneId),false);
 assert.equal(JSON.stringify(report).includes(d.s.customerId),false);
 assert.equal(renderReconciliationDashboard(report,{buyerSummary:true}).includes(d.s.milestoneId),false);
 assert.equal((await verifyAuditChain(auditPool,d.s.tenantId,{checkpoint:report.checkpoint})).ok,true);
 if(process.env.SECUREPAY_CI_REPORT_EXPORT==="true"){
  // This suite refuses non-local/non-CI databases. All records and keys here
  // are disposable synthetic fixtures, never production or buyer data.
  const {mkdir,writeFile}=await import("node:fs/promises");
  const {generateKeyPairSync}=await import("node:crypto");
  const {privateKey,publicKey}=generateKeyPairSync("ed25519");
  const envelope=signReport(report,privateKey);
  assert.equal(verifySignedReport(JSON.parse(JSON.stringify(envelope)),publicKey),true);
  await mkdir("securepay-ci-report",{mode:0o700});
  const files={
   "reconciliation.html":renderReconciliationDashboard(report),
   "buyer-summary.html":renderReconciliationDashboard(report,{buyerSummary:true}),
   "transactions.csv":reportCSV(report),
   "signed-report.json":JSON.stringify(envelope,null,2),
   "demo-public-key.pem":publicKey.export({format:"pem",type:"spki"}),
   "README.txt":"SECUREPAY SANDBOX DEMONSTRATION.\nAll records are synthetic CI fixtures. No real funds moved.\nThe ephemeral public key verifies this demonstration export only, not a production signing identity or independently anchored audit history.\nUse the redacted buyer-summary.html for a quick overview. Detailed exports contain synthetic operational identifiers.\n"
  };
  await Promise.all(Object.entries(files).map(([name,data])=>writeFile("securepay-ci-report/"+name,data,{flag:"wx",mode:0o600})));
 }
 await assert.rejects(loadReconciliationReport(reportingPool,{...actor,tenantId:other.s.tenantId}),/Reporting denied/);
 await assert.rejects(loadReconciliationReport(reportingPool,{...actor,key:randomBytes(32)}),/Reporting denied/);
 await assert.rejects(reportingPool.query("SELECT * FROM securepay_private.financial_journal"),e=>e.code==="42501");
 await assert.rejects(reportingPool.query("SELECT * FROM securepay_private.dispute_photos"),e=>e.code==="42501");
 await assert.rejects(reportingPool.query("SELECT * FROM securepay_private.provider_key"),e=>e.code==="42501");
 await pool.query("UPDATE securepay_private.reporting_actors SET active=false WHERE tenant_id=$1 AND actor_id=$2",[actor.tenantId,actor.actorId]);
 await assert.rejects(loadReconciliationReport(reportingPool,actor),/Reporting denied/);
});
test("report access is audited and replayed signed report IDs are denied; journal mismatches are surfaced",async()=>{
 const d=await authorizedDispute(),actor=await reportingActor(d.s.tenantId);
 await finishSettlement(d);
 const clean=await loadReconciliationReport(reportingPool,actor);assert.equal(summarizeReport(clean).mismatches,0);
 await pool.query("UPDATE securepay_private.financial_journal SET amount_cents=amount_cents-1 WHERE tenant_id=$1 AND kind='settlement_refund'",[d.s.tenantId]);
 const changed=await loadReconciliationReport(reportingPool,actor);assert.equal(summarizeReport(changed).mismatches,1);
 assert.equal(summarizeReport(changed).remainingCents,"1");
 const access=(await pool.query("SELECT count(*)::int AS n FROM securepay_private.reporting_access WHERE tenant_id=$1",[actor.tenantId])).rows[0];assert.equal(access.n,2);
 const {createHmac}=await import("node:crypto"),expiry=Math.floor(Date.now()/1000)+20;
 const args=[clean.reportId,actor.tenantId,actor.actorId,expiry];
 const mac=createHmac("sha256",actor.key).update(["sp-report-v1",...args].join(":")).digest("hex");
 const client=await reportingPool.connect();
 try{
  await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ");
  const {rows:[r]}=await client.query("SELECT securepay_private.reconciliation_report($1,$2,$3,$4,$5) AS report",[...args,mac]);
  assert.equal(r.report,null);await client.query("ROLLBACK");
 }finally{client.release();}
 assert.equal((await verifyAuditChain(auditPool,d.s.tenantId,{checkpoint:clean.checkpoint})).ok,true);
});

test("payer milestone view rejects same-tenant foreign customer and cross-tenant identifiers; does not expose financial internals",async()=>{
 const {makePayerService}=await import("../domain/payer-service.mjs");
 const s=await identityFixture(),other=await fixture("approved",s.tenantId),foreign=await identityFixture();
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[other.milestoneId,other.customerId]);
 const svc=makePayerService({pool:payerPool,signingKey:payerSigningKey,pepper});
 const base={tenantId:s.tenantId,identity:{subject:s.subject,authTime:Math.floor(Date.now()/1000)},body:{}};
 const r=await svc.view({...base,milestoneId:s.milestoneId});assert.equal(r.ok,true);
 assert.deepEqual(Object.keys(r.view).sort(),["amountCents","fundingStatus","isFinal","milestoneId","requestStatus","status"]);
 assert.equal((await svc.view({...base,milestoneId:other.milestoneId})).ok,false);
 assert.equal((await svc.view({...base,milestoneId:foreign.milestoneId})).ok,false);
 await assert.rejects(svc.view({...base,tenantId:foreign.tenantId,milestoneId:foreign.milestoneId}),/Payer context denied/);
 assert.equal((await providerEvent(s,"held")).status,"applied");
 assert.equal((await svc.view({...base,milestoneId:s.milestoneId})).view.fundingStatus,"held");
});
test("separate owner dashboard accepts only configured owner MFA audience and tenant; reporting runtime cannot move money",async()=>{
 const {startOwnerDashboard}=await import("../../server/securepay-owner.js");
 const {generateKeyPair,exportJWK,SignJWT}=await import("jose");
 const {createServer}=await import("node:http");
 const d=await authorizedDispute(),foreign=await authorizedDispute(),actor=await reportingActor(d.s.tenantId);
 const {privateKey,publicKey}=await generateKeyPair("ES256"),jwk=await exportJWK(publicKey);jwk.kid="owner";jwk.alg="ES256";
 const jwks=createServer((req,res)=>{res.setHeader("content-type","application/json");res.end(JSON.stringify({keys:[jwk]}));});
 await new Promise(r=>jwks.listen(0,"127.0.0.1",r));
 const issuer="https://owner-fixture.invalid",audience="securepay-owner",subject="owner-fixture",acr="owner-mfa";
 const env={NODE_ENV:"test",SECUREPAY_OWNER_SANDBOX_ENABLED:"true",SECUREPAY_OWNER_PORT:"0",SECUREPAY_OWNER_ISSUER:issuer,SECUREPAY_OWNER_AUDIENCE:audience,SECUREPAY_OWNER_REQUIRED_ACR:acr,SECUREPAY_OWNER_SUBJECT:subject,SECUREPAY_AUTH_AUDIENCE:"securepay-customer",
 SECUREPAY_OWNER_JWKS_URL:"http://127.0.0.1:"+jwks.address().port+"/jwks",SECUREPAY_REPORT_DATABASE_URL:reportingPool.options.connectionString,SECUREPAY_REPORT_TENANT_ID:actor.tenantId,SECUREPAY_REPORT_ACTOR_ID:actor.actorId,SECUREPAY_REPORT_ACTOR_KEY:actor.key.toString("hex")};
 let service;
 try{
  await assert.rejects(startOwnerDashboard({...env,SECUREPAY_PIN_PEPPER:"forbidden"}),/secrets forbidden/);
  await assert.rejects(startOwnerDashboard({...env,SECUREPAY_OWNER_AUDIENCE:"securepay-customer"}),/configuration incomplete/);
  await assert.rejects(startOwnerDashboard({...env,NODE_ENV:"production"}),/disabled/);
  service=await startOwnerDashboard(env);
  const base="http://127.0.0.1:"+service.server.address().port+"/v1/securepay-owner";
  const token=(sub=subject,aud=audience)=>new SignJWT({acr,auth_time:Math.floor(Date.now()/1000)}).setProtectedHeader({alg:"ES256",kid:"owner"}).setIssuer(issuer).setAudience(aud).setSubject(sub).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  const post=(body,bearer)=>fetch(base+"/report",{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+bearer},body:JSON.stringify(body)});
  const html=await fetch(base+"/dashboard");assert.equal(html.status,200);assert.equal(html.headers.get("cache-control"),"no-store");assert.match(await html.text(),/business-owner dashboard/);
  assert.equal((await post({},await token(subject,"securepay-customer"))).status,401);
  assert.equal((await post({},await token("other-owner"))).status,403);
  assert.equal((await post({tenantId:foreign.s.tenantId},await token())).status,400);
  const response=await post({},await token());assert.equal(response.status,200);
  const result=await response.json();assert.equal(result.report.tenantId,d.s.tenantId);assert.equal(result.report.milestones.length,1);assert.equal(result.summary.remainingCents,"5000");
  assert.equal(JSON.stringify(result).includes(foreign.s.milestoneId),false);
  assert.equal((await fetch(base+"/reserve",{method:"POST"})).status,404);
  await assert.rejects(reportingPool.query("SELECT securepay_private.dispatch_settlement_leg(NULL,NULL,NULL,NULL,NULL)"),e=>e.code==="42501");
 }finally{if(service)await service.close();await new Promise(r=>jwks.close(r));}
});

async function seedApprovedWork(s){
 const z=randomUUID(),owner=randomUUID(),photoId=randomUUID(),bytes=pngFixture(),digest=createHash("sha256").update(bytes).digest("hex");
 await pool.query("INSERT INTO securepay_private.work_completion(completion_id,tenant_id,milestone_id,owner_id,customer_id,amount_cents) VALUES($1,$2,$3,$4,$5,5000)",[z,s.tenantId,s.milestoneId,owner,s.customerId]);
 await pool.query("INSERT INTO securepay_private.work_photos(photo_id,completion_id,tenant_id,digest,original_digest,original_media_type,content,plaintext_size,key_id,scan_key_id) SELECT $1,$2,$3,$4,$4,'image/png',public.pgp_sym_encrypt_bytea($5::bytea,encode(secret,'hex'),'cipher-algo=aes256,compress-algo=0'),octet_length($5::bytea),key_id,'primary' FROM securepay_private.evidence_keys WHERE write_enabled",[photoId,z,s.tenantId,digest,bytes]);
 await pool.query("INSERT INTO securepay_private.work_photo_views(tenant_id,completion_id,photo_id,customer_id) VALUES($1,$2,$3,$4)",[s.tenantId,z,photoId,s.customerId]);
 await pool.query("UPDATE securepay_private.work_completion SET status='approved',manifest_digest=securepay_private.work_manifest($1),approved_version=0 WHERE completion_id=$1",[z]);
 await pool.query("INSERT INTO securepay_private.work_approvals(completion_id,tenant_id,customer_id,manifest_digest,amount_cents,approved_version) SELECT completion_id,tenant_id,customer_id,manifest_digest,amount_cents,approved_version FROM securepay_private.work_completion WHERE completion_id=$1",[z]);
}
async function completionFixture(){
 const s=await identityFixture({approved:false});
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2 WHERE id=$1",[s.milestoneId,s.customerId]);
 const actorId=randomUUID(),key=randomBytes(32),scope={tenantId:s.tenantId,milestoneId:s.milestoneId,completionId:randomUUID()};
 await pool.query("INSERT INTO securepay_private.dispute_actors(tenant_id,actor_id,role,secret) VALUES($1,$2,'owner',$3)",[s.tenantId,actorId,key]);
 await pool.query("INSERT INTO securepay_private.work_assignments(tenant_id,milestone_id,owner_id) VALUES($1,$2,$3)",[s.tenantId,s.milestoneId,actorId]);
 const scanner=makeEvidenceScanner({key:scanKey,scan:async()=>"clean",purpose:"completion"});
 const owner=makeWorkCompletionOwner({pool:completionPool,actorId,key,scanner});
 const {makePayerService}=await import("../domain/payer-service.mjs");
 const svc=makePayerService({pool:payerPool,signingKey:payerSigningKey,pepper});
 const payer={tenantId:s.tenantId,milestoneId:s.milestoneId,identity:{subject:s.subject,authTime:Math.floor(Date.now()/1000)}};
 return {s,scope,actorId,key,owner,svc,payer,scanner};
}
test("mandatory work evidence and inspection approval gate ordinary PIN reservation and provider dispatch",async()=>{
 const d=await completionFixture(),{s,scope,owner,svc,payer}=d;
 const g=await changeGrant(s);assert.equal((await asPayer(s,c=>changePin(c,g,pepper))).ok,true);
 const reserve=()=>svc.reserve({...payer,body:{pin:s.pin,expectedAmountCents:5000,idempotencyKey:randomUUID()}});
 assert.equal((await reserve()).ok,false);
 assert.equal((await owner.start(scope)).ok,true);
 assert.equal((await owner.submit(scope)).ok,false);
 const raw=pngFixture(),p=await owner.upload({...scope,mediaType:"image/png",content:raw});
 assert.equal(p.ok,true);
 const q=await owner.upload({...scope,mediaType:"image/png",content:pngFixture()});assert.equal(q.ok,true);
 const row=(await pool.query("SELECT content FROM securepay_private.work_photos WHERE photo_id=$1",[p.photoId])).rows[0];
 assert.notDeepEqual(row.content,raw);
 assert.equal((await owner.submit({...scope,comments:"Work completed as agreed"})).ok,true);
 assert.equal((await owner.upload({...scope,mediaType:"image/png",content:pngFixture()})).ok,false);
 assert.equal((await reserve()).ok,false);
 const now=(await svc.completion({...payer,body:{}})).completion;
 assert.equal(now.photos.length,2);assert.equal(now.comments,"Work completed as agreed");
 const body={completionId:now.completionId,manifestDigest:now.manifestDigest,expectedAmountCents:5000,version:now.version};
 assert.equal((await svc.approve({...payer,body})).ok,false);
 const first=await svc.photo({...payer,body:{photoId:p.photoId}});assert.equal(first.ok,true);assert.deepEqual(Buffer.from(first.photo.content,"base64"),raw);
 assert.equal((await svc.approve({...payer,body})).ok,false);
 assert.equal((await svc.photo({...payer,body:{photoId:q.photoId}})).ok,true);
 assert.equal((await svc.approve({...payer,body:{...body,expectedAmountCents:4999}})).ok,false);
 assert.equal((await svc.approve({...payer,body:{...body,manifestDigest:"0".repeat(64)}})).ok,false);
 assert.equal((await svc.approve({...payer,body:{...body,version:"0"}})).ok,false);
 const approvals=await Promise.all([svc.approve({...payer,body}),svc.approve({...payer,body})]);assert.equal(approvals.filter(r=>r.ok).length,1);
 const reserved=await reserve();assert.equal(reserved.ok,true);
 assert.equal((await provider.beginDispatch({...s,requestId:reserved.releaseRequestId})).ok,true);
 assert.equal((await providerEvent(s,"released",{requestId:reserved.releaseRequestId,transactionRef:randomUUID()})).status,"applied");
 assert.equal((await state(s)).status,"released");assert.equal((await verifyAuditChain(auditPool,s.tenantId)).ok,true);
});
test("work evidence is tenant and owner scoped, with scanner domain separation and no direct mutation",async()=>{
 const d=await completionFixture(),foreign=await completionFixture(),{scope,owner,svc,payer}=d;
 assert.equal((await foreign.owner.start(scope)).ok,false);
 assert.equal((await owner.start(scope)).ok,true);
 const bad=makeWorkCompletionOwner({pool:completionPool,actorId:d.actorId,key:d.key,scanner:makeEvidenceScanner({key:scanKey,scan:async()=>"infected",purpose:"completion"})});
 assert.equal((await bad.upload({...scope,mediaType:"image/png",content:pngFixture()})).ok,false);
 const wrongDomain=makeWorkCompletionOwner({pool:completionPool,actorId:d.actorId,key:d.key,scanner});
 assert.equal((await wrongDomain.upload({...scope,mediaType:"image/png",content:pngFixture()})).ok,false);
 const p=await owner.upload({...scope,mediaType:"image/png",content:pngFixture()});assert.equal(p.ok,true);
 assert.equal((await svc.photo({...payer,body:{photoId:p.photoId}})).ok,false);
 assert.equal((await owner.submit(scope)).ok,true);
 await assert.rejects(svc.photo({...foreign.payer,tenantId:scope.tenantId,milestoneId:scope.milestoneId,body:{photoId:p.photoId}}),/Payer context denied/);
 assert.equal((await svc.photo({...payer,milestoneId:foreign.scope.milestoneId,body:{photoId:p.photoId}})).ok,false);
 for(const role of [completionPool,payerPool,providerPool]){
  await assert.rejects(role.query("SELECT content FROM securepay_private.work_photos"),e=>e.code==="42501");
  await assert.rejects(role.query("UPDATE securepay_private.work_completion SET status='approved'"),e=>e.code==="42501");
 }
});
test("approved milestone status alone cannot bypass photo manifest or approval, and changed version blocks dispatch",async()=>{
 const s=await identityFixture({approved:false});
 await pool.query("UPDATE securepay_milestones SET payer_customer_id=$2,status='approved' WHERE id=$1",[s.milestoneId,s.customerId]);
 const grant=await changeGrant(s);
 assert.equal((await asPayer(s,c=>changePin(c,grant,pepper))).ok,true);
 const reserve=()=>asPayer(s,c=>authorizePayerInTransaction(c,{...s,expectedAmountCents:5000,requestId:randomUUID(),idempotencyKey:randomUUID()},pepper));
 assert.equal((await reserve()).ok,false);
 await seedApprovedWork(s);
 const r=await reserve();assert.equal(r.ok,true);
 await pool.query("UPDATE securepay_milestones SET version=version+1 WHERE id=$1",[s.milestoneId]);
 assert.equal((await provider.beginDispatch({...s,requestId:r.releaseRequestId})).ok,false);
 assert.equal((await state(s)).status,"release_pending");
});

async function submittedWork(d,scope=d.scope){
 assert.equal((await d.owner.start(scope)).ok,true);
 const bytes=pngFixture(),p=await d.owner.upload({...scope,mediaType:"image/png",content:bytes});assert.equal(p.ok,true);
 assert.equal((await d.owner.submit(scope)).ok,true);
 const w=(await d.svc.completion({...d.payer,body:{}})).completion;
 assert.equal((await d.svc.photo({...d.payer,body:{photoId:p.photoId}})).ok,true);
 return {w,p,bytes};
}
test("rejected completion preserves original manifest and requires a new screened revision and fresh customer approval",async()=>{
 const d=await completionFixture(),first=await submittedWork(d);
 const action={completionId:first.w.completionId,manifestDigest:first.w.manifestDigest,version:first.w.version,reason:"Required finish was not completed"};
 assert.equal((await d.svc.reject({...d.payer,body:action})).ok,true);
 assert.equal((await d.svc.reject({...d.payer,body:action})).ok,false);
 const state1=await d.owner.status(d.scope);assert.equal(state1.view.current,null);assert.equal(state1.view.rejections[0].reason,action.reason);
 const second=await submittedWork(d,{...d.scope,completionId:randomUUID()});
 assert.notEqual(second.w.manifestDigest,first.w.manifestDigest);
 assert.equal((await d.svc.approve({...d.payer,body:{completionId:first.w.completionId,manifestDigest:first.w.manifestDigest,version:first.w.version,expectedAmountCents:5000}})).ok,false);
 assert.equal((await d.svc.approve({...d.payer,body:{completionId:second.w.completionId,manifestDigest:second.w.manifestDigest,version:second.w.version,expectedAmountCents:5000}})).ok,true);
 const r=await pool.query("SELECT status,manifest_digest FROM securepay_private.work_completion WHERE tenant_id=$1 ORDER BY status",[d.s.tenantId]);
 assert.deepEqual(r.rows,[{status:"approved",manifest_digest:second.w.manifestDigest},{status:"rejected",manifest_digest:first.w.manifestDigest}]);
});
test("formal work dispute attaches immutable revisions and restricts linked photo access to assigned case reviewers",async()=>{
 const d=await completionFixture(),first=await submittedWork(d);
 const caseId=randomUUID(),body={caseId,severity:"serious",manifestDigest:first.w.manifestDigest,version:first.w.version,reason:"Unsafe work requires independent review"};
 assert.equal((await d.svc.dispute({...d.payer,body})).ok,true);
 assert.equal((await d.svc.dispute({...d.payer,body})).ok,false);
 assert.equal((await state(d.s)).status,"disputed");
 const scope={...d.scope,caseId};
 const actorId=randomUUID(),key=randomBytes(32);
 await pool.query("INSERT INTO securepay_private.dispute_actors(tenant_id,actor_id,role,secret) VALUES($1,$2,'reviewer',$3)",[d.s.tenantId,actorId,key]);
 const reviewer=makeDisputeActor({pool:disputePool,actorId,key});
 assert.equal(await reviewer.linkedEvidence(scope),null);
 await pool.query("INSERT INTO securepay_private.dispute_photo_reviewers(case_id,tenant_id,reviewer_id) VALUES($1,$2,$3)",[caseId,d.s.tenantId,actorId]);
 const linked=await reviewer.linkedEvidence(scope);assert.equal(linked.completions[0].manifestDigest,first.w.manifestDigest);
 const photo=await reviewer.linkedEvidence({...scope,photoId:first.p.photoId});assert.deepEqual(Buffer.from(photo.content,"base64"),first.bytes);
 const foreign=await completionFixture();assert.equal(await reviewer.linkedEvidence({...scope,tenantId:foreign.s.tenantId}),null);
 await pool.query("INSERT INTO securepay_private.work_retention_policy(tenant_id,milestone_id,retain_until,legal_hold,reason) VALUES($1,$2,clock_timestamp()-interval '1 day',false,'Synthetic test retention policy')",[d.s.tenantId,d.s.milestoneId]);
 assert.equal((await retentionPool.query("SELECT securepay_private.purge_work_evidence(100) AS n")).rows[0].n,0);
});
test("work evidence retention preserves open cases and legal holds and only purges closed approved policies",async()=>{
 const d=await completionFixture(),{w,p}=await submittedWork(d);
 assert.equal((await d.svc.approve({...d.payer,body:{completionId:w.completionId,manifestDigest:w.manifestDigest,version:w.version,expectedAmountCents:5000}})).ok,true);
 const g=await changeGrant(d.s);assert.equal((await asPayer(d.s,c=>changePin(c,g,pepper))).ok,true);
 const r=await d.svc.reserve({...d.payer,body:{pin:d.s.pin,expectedAmountCents:5000,idempotencyKey:randomUUID()}});assert.equal(r.ok,true);
 assert.equal((await provider.beginDispatch({...d.s,requestId:r.releaseRequestId})).ok,true);
 assert.equal((await providerEvent(d.s,"released",{requestId:r.releaseRequestId,transactionRef:randomUUID()})).status,"applied");
 const purge=async()=>(await retentionPool.query("SELECT securepay_private.purge_work_evidence(100) AS n")).rows[0].n;
 assert.equal(await purge(),0);
 await pool.query("INSERT INTO securepay_private.work_retention_policy(tenant_id,milestone_id,retain_until,legal_hold,reason) VALUES($1,$2,clock_timestamp()-interval '1 day',true,'Synthetic approved retention policy')",[d.s.tenantId,d.s.milestoneId]);
 assert.equal(await purge(),0);
 await pool.query("UPDATE securepay_private.work_retention_policy SET legal_hold=false WHERE tenant_id=$1 AND milestone_id=$2",[d.s.tenantId,d.s.milestoneId]);
 const results=await Promise.all([purge(),purge()]);assert.equal(results[0]+results[1],1);
 const row=(await pool.query("SELECT content,digest,purged_at FROM securepay_private.work_photos WHERE photo_id=$1",[p.photoId])).rows[0];assert.equal(row.content,null);assert.equal(row.digest,p.digest);assert.ok(row.purged_at);
 assert.equal((await d.svc.photo({...d.payer,body:{photoId:p.photoId}})).ok,false);
 assert.equal((await verifyAuditChain(auditPool,d.s.tenantId)).ok,true);
});
test("dedicated completion HTTP service verifies owner audience, tenant assignment and upload limits",async()=>{
 const {startCompletionService}=await import("../../server/securepay-completion.js");
 const {generateKeyPair,exportJWK,SignJWT}=await import("jose");
 const {createServer}=await import("node:http");
 const d=await completionFixture(),other=await completionFixture();
 const {privateKey,publicKey}=await generateKeyPair("ES256"),jwk=await exportJWK(publicKey);jwk.kid="completion";jwk.alg="ES256";
 const jwks=createServer((req,res)=>{res.setHeader("content-type","application/json");res.end(JSON.stringify({keys:[jwk]}));});await new Promise(r=>jwks.listen(0,"127.0.0.1",r));
 const issuer="https://completion-fixture.invalid",audience="securepay-completion",subject="owner-upload",acr="owner-mfa";
 const env={NODE_ENV:"test",SECUREPAY_COMPLETION_SANDBOX_ENABLED:"true",SECUREPAY_COMPLETION_PORT:"0",SECUREPAY_COMPLETION_ISSUER:issuer,SECUREPAY_COMPLETION_AUDIENCE:audience,SECUREPAY_COMPLETION_REQUIRED_ACR:acr,SECUREPAY_COMPLETION_SUBJECT:subject,SECUREPAY_AUTH_AUDIENCE:"securepay-customer",SECUREPAY_OWNER_AUDIENCE:"securepay-owner",SECUREPAY_COMPLETION_JWKS_URL:"http://127.0.0.1:"+jwks.address().port+"/jwks",SECUREPAY_COMPLETION_DATABASE_URL:completionPool.options.connectionString,SECUREPAY_COMPLETION_TENANT_ID:d.s.tenantId,SECUREPAY_COMPLETION_ACTOR_ID:d.actorId,SECUREPAY_COMPLETION_ACTOR_KEY:d.key.toString("hex")};
 let service;
 try{
  await assert.rejects(startCompletionService({...env,SECUREPAY_PIN_PEPPER:"forbidden"},{scanner:d.scanner}),/secrets forbidden/);
  service=await startCompletionService(env,{scanner:d.scanner});
  const base="http://127.0.0.1:"+service.server.address().port+"/v1/securepay-completion";
  const token=(aud=audience,sub=subject)=>new SignJWT({acr,auth_time:Math.floor(Date.now()/1000)}).setProtectedHeader({alg:"ES256",kid:"completion"}).setIssuer(issuer).setAudience(aud).setSubject(sub).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  const post=async(action,body={},bearer=null,id=d.s.milestoneId)=>fetch(base+"/"+id+"/"+action,{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+(bearer??await token())},body:JSON.stringify(body)});
  const page=await fetch(base+"/upload");assert.equal(page.status,200);assert.match(await page.text(),/Screen and upload photo/);
  assert.equal((await post("start",{},await token("securepay-customer"))).status,401);
  assert.equal((await post("start",{},await token(audience,"other"))).status,403);
  assert.equal((await post("start",{},null,other.s.milestoneId)).status,403);
  assert.equal((await post("start",{tenantId:other.s.tenantId})).status,400);
  const started=await post("start");assert.equal(started.status,201);const {completionId}=await started.json();
  assert.equal((await post("submit",{completionId,comments:""})).status,403);
  assert.equal((await post("upload",{completionId,mediaType:"image/png",content:"invalid!"})).status,400);
  const uploaded=await post("upload",{completionId,mediaType:"image/png",content:pngFixture().toString("base64")});assert.equal(uploaded.status,201);
  assert.equal((await post("submit",{completionId,comments:"Completed"})).status,200);
  const v=await post("status");assert.equal(v.status,200);assert.equal((await v.json()).view.current.status,"submitted");
 }finally{if(service)await service.close();await new Promise(r=>jwks.close(r));}
});

async function planFixture(){
 const d=await completionFixture(),jobId=randomUUID(),quoteDigest=randomBytes(32).toString("hex"),planId=randomUUID();
 await pool.query("INSERT INTO securepay_private.quote_assignments(tenant_id,job_id,owner_id,customer_id,quote_digest,total_cents) VALUES($1,$2,$3,$4,$5,5000)",[d.s.tenantId,jobId,d.actorId,d.s.customerId,quoteDigest]);
 const items=[{milestoneId:randomUUID(),amountCents:2000,description:"First stage",final:false},{milestoneId:randomUUID(),amountCents:3000,description:"Final completed work",final:true}];
 const scope={tenantId:d.s.tenantId,jobId,planId,items};
 return {d,scope,quoteDigest};
}
test("owner offer and exact customer acceptance materialize bilateral milestone plan once, with no pre-acceptance work or funding",async()=>{
 const {d,scope,quoteDigest}=await planFixture(),{tenantId,planId,items}=scope;
 assert.equal((await d.owner.offerPlan({...scope,items:[{...items[0],final:true},items[1]]})).ok,false);
 assert.equal((await d.owner.offerPlan({...scope,items:[{...items[0],amountCents:1000},items[1]]})).ok,false);
 assert.equal((await d.owner.offerPlan({...scope,items:[{...items[0]}, {...items[1],milestoneId:items[0].milestoneId}]})).ok,false);
 const offer=await d.owner.offerPlan(scope);assert.equal(offer.ok,true);
 assert.equal((await d.owner.start({tenantId,milestoneId:items[0].milestoneId})).ok,false);
 assert.equal((await provider.event({tenantId,milestoneId:items[0].milestoneId,kind:"funded",fundingRef:randomUUID(),amountCents:2000})).status,"denied");
 const request={...d.payer,planId,body:{}},view=(await d.svc.plan(request)).plan;
 assert.equal(view.quoteDigest,quoteDigest);assert.equal(view.planDigest,offer.planDigest);assert.deepEqual(view.items,items);
 const accept=body=>d.svc.acceptPlan({...request,body});
 assert.equal((await accept({planDigest:offer.planDigest,expectedTotalCents:4999})).ok,false);
 assert.equal((await accept({planDigest:"0".repeat(64),expectedTotalCents:5000})).ok,false);
 const foreign=await completionFixture();assert.equal((await foreign.svc.plan({...foreign.payer,planId,body:{}})).ok,false);
 const body={planDigest:view.planDigest,expectedTotalCents:5000};
 const results=await Promise.all([accept(body),accept(body)]);assert.equal(results.filter(r=>r.ok).length,1);
 assert.equal((await d.owner.withdrawPlan({tenantId,planId})).ok,false);
 const rows=(await pool.query("SELECT id,amount_cents,is_final,payer_customer_id,status FROM securepay_milestones WHERE tenant_id=$1 AND job_id=$2 ORDER BY amount_cents",[tenantId,scope.jobId])).rows;
 assert.deepEqual(rows,items.map(x=>({id:x.milestoneId,amount_cents:String(x.amountCents),is_final:x.final,payer_customer_id:d.s.customerId,status:"planned"})));
 assert.equal((await verifyAuditChain(auditPool,tenantId)).ok,true);
});
test("withdrawn or stale quote offer cannot be accepted; a single final milestone is supported",async()=>{
 const {d,scope}=await planFixture(),offer=await d.owner.offerPlan(scope);assert.equal(offer.ok,true);
 assert.equal((await d.owner.withdrawPlan(scope)).ok,true);
 assert.equal((await d.svc.acceptPlan({...d.payer,planId:scope.planId,body:{planDigest:offer.planDigest,expectedTotalCents:5000}})).ok,false);
 const single={...scope,planId:randomUUID(),items:[{milestoneId:randomUUID(),amountCents:5000,description:"Entire agreed work",final:true}]};
 const next=await d.owner.offerPlan(single);assert.equal(next.ok,true);
 await pool.query("UPDATE securepay_private.quote_assignments SET quote_digest=$3 WHERE tenant_id=$1 AND job_id=$2",[scope.tenantId,scope.jobId,randomBytes(32).toString("hex")]);
 assert.equal((await d.svc.acceptPlan({...d.payer,planId:single.planId,body:{planDigest:next.planDigest,expectedTotalCents:5000}})).ok,false);
});
test("final stage submission requires confirmed and balanced preceding stages",async()=>{
 const {d,scope}=await planFixture(),offer=await d.owner.offerPlan(scope);
 assert.equal((await d.svc.acceptPlan({...d.payer,planId:scope.planId,body:{planDigest:offer.planDigest,expectedTotalCents:5000}})).ok,true);
 const [one,two]=scope.items;
 const finalScope={tenantId:scope.tenantId,milestoneId:two.milestoneId,completionId:randomUUID()};
 assert.equal((await d.owner.start(finalScope)).ok,true);
 assert.equal((await d.owner.upload({...finalScope,mediaType:"image/png",content:pngFixture()})).ok,true);
 await assert.rejects(d.owner.submit(finalScope),/Prior milestones require confirmed reconciliation/);
 const s={...d.s,milestoneId:one.milestoneId,fundingRef:randomUUID()},payer={...d.payer,milestoneId:one.milestoneId},work={tenantId:s.tenantId,milestoneId:s.milestoneId,completionId:randomUUID()};
 assert.equal((await provider.event({...s,kind:"funded",amountCents:2000})).status,"applied");
 assert.equal((await d.owner.start(work)).ok,true);
 const photo=await d.owner.upload({...work,mediaType:"image/png",content:pngFixture()});assert.equal(photo.ok,true);
 assert.equal((await d.owner.submit(work)).ok,true);
 const w=(await d.svc.completion({...payer,body:{}})).completion;
 assert.equal((await d.svc.photo({...payer,body:{photoId:photo.photoId}})).ok,true);
 assert.equal((await d.svc.approve({...payer,body:{completionId:w.completionId,manifestDigest:w.manifestDigest,expectedAmountCents:2000,version:w.version}})).ok,true);
 const g=await changeGrant(s);assert.equal((await asPayer(s,c=>changePin(c,g,pepper))).ok,true);
 const reserve=await d.svc.reserve({...payer,body:{pin:s.pin,expectedAmountCents:2000,idempotencyKey:randomUUID()}});assert.equal(reserve.ok,true);
 await assert.rejects(d.owner.submit(finalScope),/Prior milestones require confirmed reconciliation/);
 assert.equal((await provider.beginDispatch({...s,requestId:reserve.releaseRequestId})).ok,true);
 assert.equal((await provider.event({...s,kind:"released",amountCents:2000,requestId:reserve.releaseRequestId,transactionRef:randomUUID()})).status,"applied");
 assert.equal((await d.owner.submit(finalScope)).ok,true);
 assert.equal((await state({milestoneId:two.milestoneId})).status,"submitted");
});
