// Every registered tenant-scoped API route must reject a valid identity from a different business.
// This is intentionally a separate process from the main API tests, avoiding shared rate-limit state.
// Run against the migrated PostgreSQL schema using the restricted runtime connection.
import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomBytes} from "node:crypto";
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
   "($1,$3,'read_only','active'),($2,$4,'read_only','active') "+
   "ON CONFLICT(tenant_id,user_id) DO UPDATE SET role='read_only',status='active'",
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
 }finally{
  await new Promise(resolve=>api.close(resolve));
  await admin.end();
  await appPool.end();
  await new Promise(resolve=>jwksServer.close(resolve));
 }
});
