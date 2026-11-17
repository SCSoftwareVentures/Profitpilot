import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomUUID} from "node:crypto";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";
import {hasRecentMfa} from "../server/auth.js";

test("step-up requires explicit recent MFA and a consistent authentication time",()=>{
 const now=1800000000,valid={mfa:true,authTime:now-120,issuedAt:now-30};
 assert.equal(hasRecentMfa(valid,now),true);
 for(const changed of [{mfa:false},{mfa:"true"},{authTime:undefined},{authTime:now-301},{authTime:now+6},{authTime:"1800000000"},{authTime:now-10,issuedAt:now-20},{issuedAt:undefined}]){
  assert.equal(hasRecentMfa({...valid,...changed},now),false);
 }
});

test("single calculation export requires fresh issuer MFA, owner/admin role, tenant scope and a durable minimal audit",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:45000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const tenant="33333333-3333-4333-8333-333333333333",foreignRun="29292929-2929-4929-8929-292929292929";
 const owner=randomUUID(),subject="ci-export-"+owner,run=randomUUID(),sensitive="SYNTHETIC_PRIVATE_VALUE";
 const issuer="https://profitpilot-export-ci.invalid/",audience="profitpilot-api";
 const {privateKey,publicKey}=await generateKeyPair("RS256");
 const jwk={...await exportJWK(publicKey),kid:"ci-export-key",use:"sig",alg:"RS256"};
 const jwks=createServer((req,res)=>{res.writeHead(200,{"content-type":"application/json"});res.end(JSON.stringify({keys:[jwk]}));});
 await new Promise(resolve=>jwks.listen(0,"127.0.0.1",resolve));
 Object.assign(process.env,{NODE_ENV:"test",DATABASE_URL:process.env.TEST_APP_DATABASE_URL,AUTH_ISSUER:issuer,AUTH_AUDIENCE:audience,AUTH_JWKS_URL:"http://127.0.0.1:"+jwks.address().port+"/jwks"});
 const {default:app}=await import("../server/index.js");
 const {pool,withTenant}=await import("../server/db.js");
 const api=createServer(app);
 await new Promise(resolve=>api.listen(0,"127.0.0.1",resolve));
 const base="http://127.0.0.1:"+api.address().port;
 const claims=()=>({amr:["pwd","mfa"],auth_time:Math.floor(Date.now()/1000)-10});
 async function request(runId,{who=subject,tenantId=tenant,extra=claims(),body={purpose:"internal_review"},authenticated=true}={}){
  const headers={"content-type":"application/json"};
  if(authenticated)headers.authorization="Bearer "+await new SignJWT(extra).setProtectedHeader({alg:"RS256",kid:jwk.kid}).setIssuer(issuer).setAudience(audience).setSubject(who).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  return fetch(base+"/v1/tenants/"+tenantId+"/calculations/"+runId+"/export",{method:"POST",headers,body:JSON.stringify(body)});
 }
 try{
  await admin.query("INSERT INTO users(id,auth_subject,email,status) VALUES($1,$2,'export@example.invalid','active')",[owner,subject]);
  await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES($1,$2,'owner','active')",[tenant,owner]);
  await admin.query("INSERT INTO calculation_runs(id,tenant_id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_by) VALUES($1,$2,'cccccccc-cccc-4ccc-8ccc-cccccccccccc','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','2026-01-01','2026-01-31','ci-export','{}',$3,'incomplete',$4)",[run,tenant,JSON.stringify({currency:"AUD",revenue:"100.00",deliveryCost:"50.00",indicativeContribution:"50.00",contribution:"50.00",marginPercent:"50.00",privateNote:sensitive}),owner]);
  assert.equal((await request(run,{authenticated:false})).status,401);
  assert.equal((await request(run,{extra:{}})).status,403);
  assert.equal((await request(run,{extra:{...claims(),auth_time:Math.floor(Date.now()/1000)-600}})).status,403);
  assert.equal((await request(run,{extra:{...claims(),amr:["pwd"]}})).status,403);
  const membership=await withTenant(tenant,subject,c=>c.query("SELECT private.current_tenant_id() AS tenant, private.current_actor_role() AS role"));
  assert.deepEqual(membership.rows[0],{tenant,role:"owner"},"fixture owner must have a valid signed tenant context");
  const invalidBody=await request(run,{body:{purpose:"internal_review",includePayroll:true}});
  assert.equal(invalidBody.status,400,"fresh owner request: "+await invalidBody.text());
  assert.equal((await request(foreignRun)).status,404);
  assert.equal((await request(foreignRun,{tenantId:"44444444-4444-4444-8444-444444444444"})).status,403);
  assert.equal((await request(run,{who:"isolation-tenant-c"})).status,403);
  await assert.rejects(()=>withTenant(tenant,"isolation-tenant-c",c=>c.query("SELECT private.export_calculation_summary($1,$2,$3)",[tenant,run,"internal_review"])),/authority denied/i);
  assert.equal((await admin.query("SELECT id FROM private.calculation_export_events WHERE calculation_id=$1",[run])).rowCount,0);
  const response=await request(run);
  assert.equal(response.status,200,"fresh owner export: "+await response.clone().text());
  assert.match(response.headers.get("cache-control"),/no-store/);
  assert.match(response.headers.get("content-disposition"),/attachment/);
  const summary=await response.json();
  assert.equal(summary.calculationId,run);
  assert.equal(summary.revenue,"100.00");assert.equal(summary.indicativeContribution,"50.00");
  assert.equal(summary.contribution,null);assert.equal(summary.marginPercent,null);
  assert.ok(!JSON.stringify(summary).includes(sensitive));
  const event=await admin.query("SELECT tenant_id,actor_user_id,calculation_id,purpose FROM private.calculation_export_events WHERE id=$1",[summary.exportId]);
  assert.deepEqual(event.rows[0],{tenant_id:tenant,actor_user_id:owner,calculation_id:run,purpose:"internal_review"});
  await assert.rejects(()=>withTenant(tenant,subject,c=>c.query("DELETE FROM private.calculation_export_events")),/permission denied/i);
  await admin.query("UPDATE tenant_memberships SET status='revoked' WHERE tenant_id=$1 AND user_id=$2",[tenant,owner]);
  assert.equal((await request(run)).status,403);
  assert.equal((await admin.query("SELECT id FROM private.calculation_export_events WHERE calculation_id=$1",[run])).rowCount,1);
 }finally{await new Promise(resolve=>api.close(resolve));await new Promise(resolve=>jwks.close(resolve));await Promise.all([pool.end(),admin.end()]);}
});
