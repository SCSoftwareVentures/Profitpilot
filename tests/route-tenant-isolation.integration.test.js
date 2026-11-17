// Every registered tenant-scoped API route must reject a valid identity from a different business.
// This is intentionally a separate process from the main API tests, avoiding shared rate-limit state.
// Run against the migrated PostgreSQL schema using the restricted runtime connection.
import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomBytes,randomUUID} from "node:crypto";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

const enabled=Boolean(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_APP_DATABASE_URL);
test("every tenant-scoped API route denies cross-business accounts before request handling",{
 skip:!enabled
},async()=>{
 const tenantA="11111111-1111-4111-8111-111111111111";
 const tenantB="22222222-2222-4222-8222-222222222222";
 const userA="abcabcab-1111-4111-8111-111111111111";
 const userB="bcbcbcbc-2222-4222-8222-222222222222";
 const subjectA="ci-route-a";
 const subjectB="ci-route-b";
 const issuer="https://profitpilot-ci.invalid/";
 const {publicKey,privateKey}=await generateKeyPair("RS256");
 const jwk=await exportJWK(publicKey);
 Object.assign(jwk,{kid:"profitpilot-route-audit",use:"sig",alg:"RS256"});
 const jwksServer=createServer((req,res)=>{
  if(req.url!=="/.well-known/jwks.json"){res.writeHead(404).end();return;}
  res.writeHead(200,{"content-type":"application/json","cache-control":"no-store"});
  res.end(JSON.stringify({keys:[jwk]}));
 });
 await new Promise(resolve=>jwksServer.listen(0,"127.0.0.1",resolve));
 process.env.NODE_ENV="test";
 process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 process.env.AUTH_ISSUER=issuer;
 process.env.AUTH_AUDIENCE="profitpilot-api";
 process.env.AUTH_STEP_UP_ACR="urn:profitpilot:step-up";
 process.env.AUTH_JWKS_URL="http://127.0.0.1:"+jwksServer.address().port+"/.well-known/jwks.json";
 if(!process.env.TENANT_CONTEXT_HMAC_SECRET)throw new Error("Tenant signing key required");
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const {default:app}=await import("../server/index.js");
 const {pool:appPool}=await import("../server/db.js");
 const api=createServer(app);
 await new Promise(resolve=>api.listen(0,"127.0.0.1",resolve));
 try{
  await admin.query(
   "INSERT INTO tenants(id,legal_name) VALUES ($1,'Route audit A'),($2,'Route audit B') ON CONFLICT(id) DO NOTHING",
   [tenantA,tenantB]);
  await admin.query(
   "INSERT INTO users(id,auth_subject,email,status) VALUES "+
   "($1,$3,'route-a@example.invalid','active'),($2,$4,'route-b@example.invalid','active') "+
   "ON CONFLICT (auth_subject) DO UPDATE SET status='active'",
   [userA,userB,subjectA,subjectB]);
  await admin.query(
   "UPDATE users SET auth_issuer=$1 WHERE auth_subject=ANY($2::text[]) AND auth_issuer IS NULL",
   [issuer,[subjectA,subjectB]]);
  await admin.query(
   "INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES "+
   "($1,$3,'owner','active'),($2,$4,'owner','active') "+
   "ON CONFLICT(tenant_id,user_id) DO UPDATE SET role='owner',status='active'",
   [tenantA,tenantB,userA,userB]);
  const jwt=async subject=>new SignJWT({
   email:subject+"@example.invalid",
   auth_time:Math.floor(Date.now()/1000),
   acr:"urn:profitpilot:step-up",
   amr:["pwd","mfa"]
  }).setProtectedHeader({alg:"RS256",kid:jwk.kid})
   .setIssuer(issuer).setAudience("profitpilot-api").setSubject(subject)
   .setIssuedAt().setExpirationTime("5m")
   .setJti(randomBytes(16).toString("hex")).sign(privateKey);
  const tokens={a:await jwt(subjectA),b:await jwt(subjectB)};
  const base="http://127.0.0.1:"+api.address().port;
  async function send(method,path,token){
   const mutation=method!=="GET";
   return fetch(base+path,{
    method,
    headers:{authorization:"Bearer "+token,...(mutation?{"content-type":"application/json"}:{})},
    body:mutation?JSON.stringify({tenantId:tenantB,requestId:userA,eraseEmail:false}):undefined
   });
  }
  // Control cases prove both identities are live and their own tenant is accessible.
  assert.equal((await send("GET","/v1/tenants/"+tenantA+"/contracts",tokens.a)).status,200);
  assert.equal((await send("GET","/v1/tenants/"+tenantB+"/contracts",tokens.b)).status,200);

  const routeLayers=app._router.stack.filter(layer=>layer.route);
  const tenantRoutes=routeLayers.filter(layer=>
   typeof layer.route.path==="string"&&layer.route.path.startsWith("/v1/tenants"));
  assert.ok(tenantRoutes.length>=20,"tenant route inventory unexpectedly shrank; review route registration");
  for(const layer of tenantRoutes){
   const route=layer.route;
   assert.match(route.path,/^\/v1\/tenants\/:tenantId(?:\/|$)/,
    "tenant API routes must use an authenticated tenantId path: "+route.path);
   assert.equal(route.stack[0]?.name,"membership",
    "tenant membership guard must run before all handlers: "+route.path);
   const methods=Object.keys(route.methods).filter(method=>route.methods[method]);
   assert.ok(methods.length>0,"route without registered HTTP method: "+route.path);
   for(const method of methods){
    const params={requestId:userA,batchId:userA,matchId:userA,runId:userA,
     userId:userA,permissionKey:"imports.create"};
    const resolvePath=tenantId=>route.path.replace(/:([a-zA-Z]\w*)/g,(match,key)=>{
     if(key==="tenantId")return tenantId;
     assert.ok(Object.hasOwn(params,key),"unclassified route parameter: "+route.path+" / "+key);
     return params[key];
    });
    for(const [tenantId,credential] of [[tenantB,tokens.a],[tenantA,tokens.b]]){
     const response=await send(method.toUpperCase(),resolvePath(tenantId),credential);
     assert.equal(response.status,403,
      method.toUpperCase()+" "+route.path+" accepted or mishandled a cross-business user");
     assert.equal(response.headers.get("cache-control"),"no-store",
      "authorization errors must not be cached: "+route.path);
    }
   }
  }

  // BOLA/IDOR regression: a valid tenant owner must not read or mutate a real
  // object belonging to another active organization, even with full local role rights.
  const fixture=async(tenantId,actorId,marker)=>{
   const ids={business:randomUUID(),site:randomUUID(),contract:randomUUID(),
    batch:randomUUID(),invoice:randomUUID(),line:randomUUID(),match:randomUUID(),
    calculation:randomUUID(),privacy:randomUUID()};
   await admin.query(
    "INSERT INTO businesses(id,tenant_id,name) VALUES($1,$2,$3)",
    [ids.business,tenantId,"Object audit "+marker]);
   await admin.query(
    "INSERT INTO sites(id,tenant_id,business_id,name) VALUES($1,$2,$3,$4)",
    [ids.site,tenantId,ids.business,"Object audit site "+marker]);
   await admin.query(
    "INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES($1,$2,$3,$4,'active')",
    [ids.contract,tenantId,ids.business,"Object audit contract "+marker]);
   await admin.query(
    "INSERT INTO import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) "+
    "VALUES($1,$2,'customer_invoice','CI object access','uploaded',$3,$4,$5)",
    [ids.batch,tenantId,randomBytes(32).toString("hex"),"object-audit-"+marker+".csv",actorId]);
   await admin.query(
    "INSERT INTO invoices(id,tenant_id,direction,invoice_number,invoice_date,total_amount,tax_basis,source_ref) "+
    "VALUES($1,$2,'customer',$3,'2026-01-15',100,'no_gst','ci-idor')",
    [ids.invoice,tenantId,"obj-"+randomUUID()]);
   await admin.query(
    "INSERT INTO invoice_lines(id,tenant_id,invoice_id,line_number,description,amount) "+
    "VALUES($1,$2,$3,1,'test line',100)",
    [ids.line,tenantId,ids.invoice]);
   await admin.query(
    "INSERT INTO match_reviews(id,tenant_id,invoice_line_id,contract_id,site_id,confidence,decision) "+
    "VALUES($1,$2,$3,$4,$5,'HIGH','candidate')",
    [ids.match,tenantId,ids.line,ids.contract,ids.site]);
   await admin.query(
    "INSERT INTO calculation_runs(id,tenant_id,contract_id,site_id,period_start,period_end,"+
    "formula_version,inputs,outputs,completeness,created_by) "+
    "VALUES($1,$2,$3,$4,'2026-01-01','2026-01-31','object-test','{}','{}','incomplete',$5)",
    [ids.calculation,tenantId,ids.contract,ids.site,actorId]);
   await admin.query(
    "INSERT INTO privacy_requests(id,tenant_id,subject_user_id,submitted_by,request_type,details) "+
    "VALUES($1,$2,$3,$3,'access','Object-level ownership regression request')",
    [ids.privacy,tenantId,actorId]);
   return ids;
  };
  const objectsA=await fixture(tenantA,userA,"A");
  const objectsB=await fixture(tenantB,userB,"B");
  const before={
   matchA:(await admin.query("SELECT decision FROM match_reviews WHERE id=$1",[objectsA.match])).rows[0].decision,
   matchB:(await admin.query("SELECT decision FROM match_reviews WHERE id=$1",[objectsB.match])).rows[0].decision
  };
  const bypassBody={decision:"confirmed",reason:"Cross-tenant object audit"};
  const requestBodyByAction=[
   ["confirm-account",{}],
   ["decision",{action:"verify_identity",reason:"Cross-business audit attempt"}],
   ["approve-export",{}],
   ["export",{}],
   ["approve-redaction",{targetRequestId:objectsA.privacy}],
   ["execute-redaction",{targetRequestId:objectsA.privacy}],
   ["approve-closure",{eraseEmail:false}],
   ["execute-closure",{eraseEmail:false}],
   ["withdraw",{reason:"Cross-business object audit"}]
  ];
  // Every per-object API rejects the ID of a record in the other tenant,
  // rather than merely rejecting a caller who lacks the whole tenant membership.
  for(const [ownTenant,foreign,credential,own] of [
   [tenantA,objectsB,tokens.a,objectsA],
   [tenantB,objectsA,tokens.b,objectsB]
  ]){
   const basePath="/v1/tenants/"+ownTenant;
   const call=async(method,path,body)=>{
    const response=await fetch(base+path,{
     method,headers:{authorization:"Bearer "+credential,...(method!=="GET"?{"content-type":"application/json"}:{})},
     body:method==="GET"?undefined:JSON.stringify(body||{})
    });
    assert.equal(response.status,404,
     "foreign object must be indistinguishable from a missing record: "+method+" "+path);
    return response;
   };
   await call("POST",basePath+"/imports/"+foreign.batch+"/rows",{rows:[{memo:"must not insert"}]});
   await call("POST",basePath+"/imports/"+foreign.batch+"/validate",{});
   await call("POST",basePath+"/matches/"+foreign.match+"/decision",bypassBody);
   await call("GET",basePath+"/calculations/"+foreign.calculation);
   await call("POST",basePath+"/security/permissions/overrides",{
    userId:foreign===objectsB?userB:userA,permissionKey:"imports.create",
    effect:"grant",reason:"Cross-business object audit"
   });
   // The override creation endpoint returns 404 for an absent target membership.
   for(const [suffix,body] of requestBodyByAction){
    const effectiveBody=body.targetRequestId?{...body,targetRequestId:own.privacy}:body;
    await call("POST",basePath+"/privacy/requests/"+foreign.privacy+"/"+suffix,effectiveBody);
   }
   await call("DELETE",basePath+"/security/permissions/overrides/"+(foreign===objectsB?userB:userA)+
    "/imports.create",{reason:"Cross-business object audit"});
   const outside=await fetch(base+basePath+"/calculations",{
    method:"POST",headers:{authorization:"Bearer "+credential,"content-type":"application/json"},
    body:JSON.stringify({contractId:foreign.contract,siteId:foreign.site,
     periodStart:"2026-01-01",periodEnd:"2026-01-31"})
   });
   assert.equal(outside.status,422,"foreign contract and site IDs must not produce a calculation");
  }

  // Same-tenant positive controls ensure negative tests did not simply fail
  // because the objects were missing or identities were unauthenticated.
  for(const [ownTenant,own,credential,foreign] of [
   [tenantA,objectsA,tokens.a,objectsB],
   [tenantB,objectsB,tokens.b,objectsA]
  ]){
   const ownCalc=await send("GET","/v1/tenants/"+ownTenant+"/calculations/"+own.calculation,credential);
   assert.equal(ownCalc.status,200,"authorized owner must read own calculation");
   assert.equal((await ownCalc.json()).id,own.calculation);
   const ownPrivacy=await send("GET","/v1/tenants/"+ownTenant+"/privacy/requests",credential);
   assert.equal(ownPrivacy.status,200,"authorized owner must see own request");
   const privacyList=(await ownPrivacy.json()).items.map(item=>item.id);
   assert.ok(privacyList.includes(own.privacy),"own request must be visible");
   assert.ok(!privacyList.includes(foreign.privacy),"foreign request must remain hidden");
   const ownContracts=await send("GET","/v1/tenants/"+ownTenant+"/contracts",credential);
   const contractList=(await ownContracts.json()).items.map(item=>item.id);
   assert.ok(contractList.includes(own.contract),"own contract must be visible");
   assert.ok(!contractList.includes(foreign.contract),"foreign contract must remain hidden");
   const ownQueue=await send("GET","/v1/tenants/"+ownTenant+"/privacy/requests/manage",credential);
   assert.equal(ownQueue.status,200,"own tenant manager must see its queue");
   assert.ok(!(await ownQueue.json()).items.some(item=>item.id===foreign.privacy),
    "manager queue must never contain another tenant's privacy request");
  }

  assert.equal((await admin.query("SELECT decision FROM match_reviews WHERE id=$1",[objectsA.match])).rows[0].decision,before.matchA,
   "foreign match decision attempt changed tenant A data");
  assert.equal((await admin.query("SELECT decision FROM match_reviews WHERE id=$1",[objectsB.match])).rows[0].decision,before.matchB,
   "foreign match decision attempt changed tenant B data");
  for(const [tenant,own,foreignUser] of [[tenantA,objectsA,userB],[tenantB,objectsB,userA]]){
   assert.equal((await admin.query("SELECT status FROM import_batches WHERE id=$1",[own.batch])).rows[0].status,"uploaded");
   assert.equal((await admin.query("SELECT count(*)::int AS n FROM raw_import_rows WHERE batch_id=$1",[own.batch])).rows[0].n,0);
   assert.equal((await admin.query("SELECT status FROM privacy_requests WHERE id=$1",[own.privacy])).rows[0].status,"requested");
   assert.equal((await admin.query("SELECT count(*)::int AS n FROM tenant_membership_permission_overrides WHERE tenant_id=$1 AND user_id=$2",
    [tenant,foreignUser])).rows[0].n,0,"foreign account must never acquire a permission override");
  }

 }finally{
  await new Promise(resolve=>api.close(resolve));
  await admin.end();
  await appPool.end();
  await new Promise(resolve=>jwksServer.close(resolve));
 }
});
