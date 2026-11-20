import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomUUID,generateKeyPairSync} from "node:crypto";
import {exportJWK,SignJWT} from "jose";
import pg from "pg";
const enabled=Boolean(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_APP_DATABASE_URL);
test("SecurePay S2 authenticated, idempotent, tenant-isolated append-only evidence",{skip:!enabled},async()=>{
 const a="11111111-1111-4111-8111-111111111111",b="22222222-2222-4222-8222-222222222222";
 const owner="eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",reader="ffffffff-ffff-4fff-8fff-ffffffffffff",foreign="99999999-9999-4999-8999-999999999999";
 const issuer="https://profitpilot-sp-ci.invalid/",audience="profitpilot-api";
 const {publicKey,privateKey}=generateKeyPairSync("rsa",{modulusLength:2048});
 const jwk=await exportJWK(publicKey);Object.assign(jwk,{kid:"securepay-ci-key",use:"sig",alg:"RS256"});
 const jwks=createServer((req,res)=>{if(req.url!=="/jwks"){res.writeHead(404).end();return;}res.writeHead(200,{"content-type":"application/json"}).end(JSON.stringify({keys:[jwk]}));});
 await new Promise(resolve=>jwks.listen(0,"127.0.0.1",resolve));
 process.env.NODE_ENV="test";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 process.env.AUTH_ISSUER=issuer;process.env.AUTH_AUDIENCE=audience;
 process.env.AUTH_JWKS_URL="http://127.0.0.1:"+jwks.address().port+"/jwks";
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 let api,appPool;
 try{
  await admin.query("INSERT INTO tenants(id,legal_name) VALUES($1,'SP A'),($2,'SP B') ON CONFLICT(id) DO NOTHING",[a,b]);
  await admin.query("INSERT INTO users(id,auth_subject,email) VALUES($1,'sp-s2-owner','owner@sp.invalid'),($2,'sp-s2-reader','reader@sp.invalid'),($3,'sp-s2-foreign','foreign@sp.invalid') ON CONFLICT(auth_subject) DO NOTHING",[owner,reader,foreign]);
  await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES($1,$2,'owner','active'),($1,$3,'read_only','active'),($4,$5,'owner','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status=EXCLUDED.status",[a,owner,reader,b,foreign]);
  const [{default:app},{pool,withTenant}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);appPool=pool;
  api=createServer(app);await new Promise(resolve=>api.listen(0,"127.0.0.1",resolve));
  async function request(path,{subject,method="GET",body}={}){
   const headers={};if(subject){
    const jwt=await new SignJWT({}).setProtectedHeader({alg:"RS256",kid:jwk.kid}).setIssuer(issuer).setAudience(audience).setSubject(subject).setIssuedAt().setExpirationTime("5m").sign(privateKey);
    headers.authorization="Bearer "+jwt;
   }
   if(body!==undefined)headers["content-type"]="application/json";
   const r=await fetch("http://127.0.0.1:"+api.address().port+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
   return {status:r.status,body:await r.json()};
  }
  const fixture=await admin.query("SELECT t.status AS tenant_status,u.status AS user_status,m.status AS member_status,m.role FROM tenant_memberships m JOIN users u ON u.id=m.user_id JOIN tenants t ON t.id=m.tenant_id WHERE m.tenant_id=$1 AND u.auth_subject=$2",[a,"sp-s2-owner"]);
  assert.equal(fixture.rows[0]?.role,"owner",JSON.stringify(fixture.rows));
  const signed=await withTenant(a,"sp-s2-owner",c=>c.query("SELECT private.current_tenant_id()::text AS tenant,private.actor_role() AS role,private.actor_id()::text AS actor"));
  assert.equal(signed.rows[0]?.tenant,a,JSON.stringify(signed.rows));
  assert.equal(signed.rows[0]?.role,"owner",JSON.stringify(signed.rows));
  const rootA="/v1/tenants/"+a+"/prototype/securepay-cases",rootB="/v1/tenants/"+b+"/prototype/securepay-cases";
  const payload={synthetic:true,clientRequestId:randomUUID(),jobReference:"job.sp-001",claimReference:"claim.sp-001"};
  assert.equal((await request(rootA,{method:"POST",body:payload})).status,401);
  assert.equal((await request(rootA,{subject:"sp-s2-reader",method:"POST",body:payload})).status,403);
  assert.equal((await request(rootA,{subject:"sp-s2-foreign",method:"POST",body:payload})).status,403);
  const unexpectedField=await request(rootA,{subject:"sp-s2-owner",method:"POST",body:{...payload,fundsMoved:true}});
  assert.equal(unexpectedField.status,400,JSON.stringify(unexpectedField));
  const opened=await request(rootA,{subject:"sp-s2-owner",method:"POST",body:payload});
  assert.equal(opened.status,201);assert.equal(opened.body.item.funds_moved,false);assert.equal(opened.body.item.synthetic,true);
  const caseId=opened.body.item.id;
  assert.equal((await request(rootA,{subject:"sp-s2-owner",method:"POST",body:payload})).status,200);
  assert.equal((await request(rootA,{subject:"sp-s2-owner",method:"POST",body:{...payload,jobReference:"job.changed"}})).status,409);
  const openedB=await request(rootB,{subject:"sp-s2-foreign",method:"POST",body:{...payload,clientRequestId:randomUUID()}});
  assert.equal(openedB.status,201);
  assert.equal((await request(rootA+"/"+openedB.body.item.id,{subject:"sp-s2-owner"})).status,404);
  const evidence={clientRequestId:randomUUID(),evidenceType:"claim_reported",evidenceReference:"opaque.claim.001"};
  const ep=rootA+"/"+caseId+"/evidence";
  assert.equal((await request(ep,{subject:"sp-s2-reader",method:"POST",body:evidence})).status,403);
  const created=await request(ep,{subject:"sp-s2-owner",method:"POST",body:evidence});
  assert.equal(created.status,201);assert.equal(created.body.item.externally_verified,false);
  assert.equal((await request(ep,{subject:"sp-s2-owner",method:"POST",body:evidence})).status,200);
  assert.equal((await request(ep,{subject:"sp-s2-owner",method:"POST",body:{...evidence,evidenceReference:"other.reference"}})).status,409);
  const listing=await request(ep,{subject:"sp-s2-owner"});assert.equal(listing.status,200);
  assert.equal(listing.body.items.length,1);assert.equal(listing.body.externalVerification,false);
  assert.equal((await request(rootA+"/"+openedB.body.item.id+"/evidence",{subject:"sp-s2-owner"})).status,404);
  await assert.rejects(()=>withTenant(a,"sp-s2-owner",c=>c.query(
   "UPDATE securepay_case_rehearsals SET status='evidence_pending' WHERE tenant_id=$1 AND id=$2",[a,caseId])),/permission denied|append-only/i);
  await assert.rejects(()=>withTenant(a,"sp-s2-owner",c=>c.query(
   "INSERT INTO securepay_evidence_rehearsals(tenant_id,case_id,client_request_id,recorded_by,evidence_type,evidence_reference) VALUES($1,$2,$3,$4,'operator_review_note','forged.actor')",[a,caseId,randomUUID(),reader])),/row-level security|permission denied/i);
  const hidden=await withTenant(a,"sp-s2-owner",c=>c.query("SELECT count(*)::int AS n FROM securepay_case_rehearsals WHERE tenant_id=$1",[b]));
  assert.equal(hidden.rows[0].n,0);
  const denied=await withTenant(a,"sp-s2-reader",c=>c.query("SELECT count(*)::int AS n FROM securepay_case_rehearsals WHERE tenant_id=$1",[a]));
  assert.equal(denied.rows[0].n,0);
 }finally{
  if(api)await new Promise(resolve=>api.close(resolve));
  if(appPool)await appPool.end();
  await admin.end();
  await new Promise(resolve=>jwks.close(resolve));
 }
});
