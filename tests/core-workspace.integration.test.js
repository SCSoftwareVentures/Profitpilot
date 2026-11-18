import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {createServer} from "node:http";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

test("core workspace is atomic, idempotent, tenant-scoped and financially unapproved",{skip:!process.env.TEST_APP_DATABASE_URL,timeout:45000},async()=>{
 const tenant=randomUUID(),other=randomUUID(),owner=randomUUID(),reader=randomUUID(),otherOwner=randomUUID();
 const setupId=randomUUID(),body={setupId,businessName:"CI Synthetic Business",siteName:"CI Synthetic Site",customerName:"CI Synthetic Customer",effectiveFrom:"2026-11-01",price:"12345.67",currency:"AUD",taxBasis:"gst_exclusive",billingBasis:"monthly"};
 const issuer="https://profitpilot-ci.invalid/",audience="profitpilot-api";
 const {publicKey,privateKey}=await generateKeyPair("RS256");
 const jwk=await exportJWK(publicKey);Object.assign(jwk,{kid:"ci-workspace",use:"sig",alg:"RS256"});
 const jwks=createServer((_req,res)=>{res.setHeader("Content-Type","application/json");res.end(JSON.stringify({keys:[jwk]}));});
 await new Promise(resolve=>jwks.listen(0,"127.0.0.1",resolve));
 Object.assign(process.env,{NODE_ENV:"test",DATABASE_URL:process.env.TEST_APP_DATABASE_URL,AUTH_ISSUER:issuer,AUTH_AUDIENCE:audience,AUTH_JWKS_URL:"http://127.0.0.1:"+jwks.address().port+"/.well-known/jwks.json"});
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const [{default:app},{pool,withTenant}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);
 const api=createServer(app);await new Promise(resolve=>api.listen(0,"127.0.0.1",resolve));
 const base="http://127.0.0.1:"+api.address().port;
 const token=subject=>new SignJWT({email:subject+"@example.invalid",auth_time:Math.floor(Date.now()/1000)-10,sid:"ci-workspace-"+subject}).setProtectedHeader({alg:"RS256",kid:jwk.kid}).setIssuer(issuer).setAudience(audience).setSubject(subject).setIssuedAt().setExpirationTime("5m").sign(privateKey);
 const req=async(t,subject,method="GET",suffix="",data)=>fetch(base+"/v1/tenants/"+t+"/workspaces"+suffix,{method,headers:{...(subject?{Authorization:"Bearer "+await token(subject)}:{}),...(data?{"Content-Type":"application/json"}:{})},body:data?JSON.stringify(data):undefined});
 try{
  await admin.query("INSERT INTO public.tenants(id,legal_name) VALUES($1,'CI Workspace Tenant'),($2,'CI Other Workspace Tenant')",[tenant,other]);
  await admin.query("INSERT INTO public.users(id,auth_subject,email) VALUES($1,'ci-workspace-owner','owner@example.invalid'),($2,'ci-workspace-reader','reader@example.invalid'),($3,'ci-workspace-other','other@example.invalid')",[owner,reader,otherOwner]);
  await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,'owner'),($1,$3,'read_only'),($4,$5,'owner')",[tenant,owner,reader,other,otherOwner]);
  const ownerSubject="ci-workspace-owner",readerSubject="ci-workspace-reader",otherSubject="ci-workspace-other";
  assert.equal((await req(tenant,null,"POST","",body)).status,401);
  assert.equal((await req(tenant,readerSubject,"POST","",body)).status,403);
  assert.equal((await req(tenant,otherSubject,"POST","",body)).status,403);
  assert.equal((await req(tenant,ownerSubject,"POST","",{...body,price:12345.67})).status,400);
  const {setupId:_,...data}=body;
  await assert.rejects(()=>pool.query("SELECT private.create_core_workspace($1,$2,$3::jsonb)",[tenant,setupId,data]),e=>e.code==="42501");
  await assert.rejects(()=>withTenant(tenant,readerSubject,c=>c.query("SELECT private.create_core_workspace($1,$2,$3::jsonb)",[tenant,setupId,data])),e=>e.code==="42501");
  await assert.rejects(()=>withTenant(tenant,ownerSubject,c=>c.query("SELECT private.create_core_workspace($1,$2,$3::jsonb)",[tenant,setupId,{...data,price:"0.001"}])),e=>e.code==="22023");
  const responses=await Promise.all([req(tenant,ownerSubject,"POST","",body),req(tenant,ownerSubject,"POST","",body)]);
  assert.deepEqual(responses.map(r=>r.status).sort(),[200,201]);
  const receipts=await Promise.all(responses.map(r=>r.json()));
  assert.equal(receipts[0].businessId,receipts[1].businessId);assert.equal(receipts[0].siteId,receipts[1].siteId);assert.equal(receipts[0].versionId,receipts[1].versionId);
  assert.equal(receipts[0].contractId,setupId);assert.equal(receipts[0].versionStatus,"draft");
  assert.equal((await req(tenant,ownerSubject,"POST","",{...body,price:"1.00"})).status,409);
  // A same-ID collision from another legitimate tenant must not retain
  // the attempted business or site record when contract insertion fails.
  assert.equal((await req(other,otherSubject,"POST","",body)).status,409);
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM public.businesses WHERE tenant_id=$1",[other])).rows[0].n,0);
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM public.sites WHERE tenant_id=$1",[other])).rows[0].n,0);
  assert.equal((await req(other,otherSubject,"GET","/"+setupId)).status,404);
  assert.equal((await req(tenant,otherSubject,"GET","/"+setupId)).status,403);
  const visible=await req(tenant,readerSubject,"GET","/"+setupId);assert.equal(visible.status,200);
  const detail=await visible.json();assert.equal(detail.price,"12345.67");assert.equal(detail.version_status,"draft");assert.equal(detail.contract_id,setupId);
  assert.ok(!Object.hasOwn(detail,"requestHash"));
  const versions=await admin.query("SELECT version_no,price::text,approved_by,approved_at FROM public.contract_versions WHERE tenant_id=$1 AND contract_id=$2",[tenant,setupId]);
  assert.deepEqual(versions.rows,[{version_no:1,price:"12345.67",approved_by:null,approved_at:null}]);
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM public.audit_events WHERE tenant_id=$1 AND object_id=$2 AND action='core_workspace_created'",[tenant,setupId])).rows[0].n,1);
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[tenant])).rows[0].ok,true);
  const incident=randomUUID();
  await admin.query("SELECT private.activate_tenant_emergency($1,$2,'suspected_compromise','CI_WORKSPACE_CONTAIN')",[tenant,incident]);
  try{
   assert.equal((await req(tenant,ownerSubject,"POST","",{...body,setupId:randomUUID()})).status,403);
   assert.equal((await req(tenant,readerSubject,"GET","/"+setupId)).status,403);
  }finally{await admin.query("SELECT private.release_tenant_emergency($1,$2,'CI_WORKSPACE_RECOVER')",[tenant,incident]);}
 }finally{
  api.closeAllConnections();jwks.closeAllConnections();await Promise.all([new Promise(r=>api.close(r)),new Promise(r=>jwks.close(r)),pool.end(),admin.end()]);
 }
});
