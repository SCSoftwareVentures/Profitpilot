import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomUUID,createHash,generateKeyPairSync} from "node:crypto";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

test("approved commercial baseline through jobs and readiness lifecycle",{skip:!process.env.TEST_ADMIN_DATABASE_URL||!process.env.TEST_APP_DATABASE_URL,timeout:60000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:2});
 const t=randomUUID(),other=randomUUID(),owner=randomUUID(),reviewer=randomUUID(),analyst=randomUUID(),reader=randomUUID();
 const identities={owner,reviewer,analyst,reader};const subjects=Object.fromEntries(Object.entries(identities).map(([k,v])=>[k,"ci-sensitive-"+v]));
 const {publicKey,privateKey}=await generateKeyPair("RS256"),jwk=await exportJWK(publicKey);
 Object.assign(jwk,{kid:"ci-sensitive",alg:"RS256",use:"sig"});
 const keys=createServer((_req,res)=>{res.setHeader("Content-Type","application/json");res.end(JSON.stringify({keys:[jwk]}));});
 await new Promise(r=>keys.listen(0,"127.0.0.1",r));
 process.env.NODE_ENV="test";process.env.SYNTHETIC_SECURITY_UI_ENABLED="true";process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 process.env.AUTH_ISSUER="https://sensitive-ci.invalid/";process.env.AUTH_AUDIENCE="profitpilot-api";
 process.env.AUTH_JWKS_URL="http://127.0.0.1:"+keys.address().port+"/jwks";
 const [{default:app},{pool:runtime}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);
 const api=createServer(app);await new Promise(r=>api.listen(0,"127.0.0.1",r));
 const base="http://127.0.0.1:"+api.address().port,authTime=Math.floor(Date.now()/1000)-10;
 const auth=async(role,opts={})=>new SignJWT({email:"verified-"+role+"@example.invalid",email_verified:true,amr:["mfa"],auth_time:authTime,sid:"ci-sensitive-"+role,...opts})
  .setProtectedHeader({alg:"RS256",kid:jwk.kid}).setIssuer(process.env.AUTH_ISSUER).setAudience(process.env.AUTH_AUDIENCE).setSubject(subjects[role]).setIssuedAt().setExpirationTime("5m").sign(privateKey);
 async function call(role,path,{tenant=t,body,claims}={}){
  const r=await fetch(base+"/v1/tenants/"+tenant+path,{method:body===undefined?"GET":"POST",headers:{authorization:"Bearer "+await auth(role,claims),...(body===undefined?{}:{"content-type":"application/json"})},body:body===undefined?undefined:JSON.stringify(body)});
  assert.match(r.headers.get("cache-control"),/no-store/);
  return {status:r.status,data:await r.json()};
 }
 const expect=async(role,path,status,opts={})=>{const result=await call(role,path,opts);assert.equal(result.status,status,path+" / "+role+" "+JSON.stringify(result.data));return result.data;};
 const hash=s=>createHash("sha256").update(s).digest("hex");
 try{
  const product=await fetch(base+"/candidate/workspace/");
  assert.equal(product.status,200);assert.match(product.headers.get("cache-control"),/no-store/);assert.match(product.headers.get("content-security-policy"),/script-src 'self'/);assert.match(await product.text(),/Operations &amp; evidence/);
  for(const asset of ["app.js","core.js","style.css"]){const response=await fetch(base+"/candidate/workspace/"+asset);assert.equal(response.status,200);assert.match(response.headers.get("cache-control"),/no-store/);}
  const screen=await fetch(base+"/candidate/security/");
  assert.equal(screen.status,200);assert.match(screen.headers.get("cache-control"),/no-store/);assert.match(screen.headers.get("content-security-policy"),/script-src 'self'/);
  assert.match(await screen.text(),/Non-production, synthetic records only/);
  const script=await fetch(base+"/candidate/security/app.js");assert.equal(script.status,200);assert.match(await script.text(),/credentials:"omit"/);
  await admin.query("INSERT INTO public.tenants(id,legal_name) VALUES($1,'Synthetic jobs API'),($2,'Synthetic jobs other')",[t,other]);
  for(const [role,id] of Object.entries(identities))await admin.query("INSERT INTO public.users(id,auth_subject,email) VALUES($1,$2,$3)",[id,subjects[role],"old-"+role+"@example.invalid"]);
  for(const [role,id] of Object.entries(identities))await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,$3)",[t,id,role==="reader"?"read_only":role==="reviewer"?"admin":role]);
  await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,'admin')",[other,reviewer]);


  const business=randomUUID(),customer=randomUUID(),site=randomUUID(),unassigned=randomUUID(),contract=randomUUID(),link=randomUUID(),otherBusiness=randomUUID(),foreignSite=randomUUID();
  const record=(kind,parentId,relatedId,label)=>({confirm:true,kind,parentId,relatedId,label});
  const path=id=>"/workspace/records/"+id,make=(id,input,role="owner",status=201,tenant=t)=>expect(role,path(id),status,{body:input,tenant});
  await make(business,record("business",null,null,"Synthetic business"),"reader",403);
  await expect("owner",path(business),403,{body:record("business",null,null,"Synthetic business"),claims:{amr:["pwd"]}});
  await make(business,record("business",null,null,"Synthetic business"));
  await make(business,record("business",null,null,"Synthetic business"),"owner",409);
  await make(otherBusiness,record("business",null,null,"Synthetic foreign business"),"reviewer",201,other);
  await make(foreignSite,record("site",otherBusiness,null,"Synthetic foreign site"),"reviewer",201,other);
  await make(customer,record("customer",business,null,"Synthetic customer"));
  await make(site,record("site",business,null,"Synthetic site"));
  await make(unassigned,record("site",business,null,"Synthetic unassigned site"));
  await make(contract,record("contract",business,customer,"Synthetic contract"));
  await make(link,record("contract_site",contract,foreignSite,null),"owner",403);
  await make(link,record("contract_site",contract,site,null));
  const listed=await expect("owner","/workspace/records-by-kind/contract",200);
  assert.deepEqual(listed.items,[{id:contract,kind:"contract",parentId:business,relatedId:customer,label:"Synthetic contract"}]);assert.equal(listed.nextCursor,null);
  assert.equal((await expect("reviewer","/workspace/records-by-kind/contract",200,{tenant:other})).items.length,0);
  await expect("reader","/workspace/records-by-kind/contract",403);
  const order=randomUUID(),version=randomUUID(),vpath="/workspace/contracts/"+contract+"/versions/"+order;
  const terms={versionId:version,periodStart:"2026-11-01",periodEnd:"2026-11-30",price:"100.00",taxBasis:"gst_exclusive",billingBasis:"monthly",evidenceDigest:hash("synthetic contract evidence")};
  const op=(step,change={})=>({confirm:true,step,...terms,...change});
  await expect("owner",vpath,403,{body:op("consume")});
  assert.equal((await expect("owner",vpath,200,{body:op("request")})).status,"requested");
  await make(randomUUID(),record("contract_site",contract,unassigned,null),"owner",409);
  assert.equal((await expect("reviewer",vpath,200)).price,"100.00");
  await expect("owner",vpath,403,{body:op("approve")});
  await expect("reviewer",vpath,403,{body:op("approve",{price:"101.00"})});
  assert.equal((await expect("reviewer",vpath,200,{body:op("approve")})).status,"approved_pending_record");
  assert.equal((await admin.query("SELECT count(*)::int n FROM public.contract_versions WHERE tenant_id=$1 AND contract_id=$2",[t,contract])).rows[0].n,0);
  await expect("reviewer",vpath,403,{body:op("consume")});
  assert.equal((await expect("owner",vpath,200,{body:op("consume")})).status,"approved_baseline");
  const stored=(await admin.query("SELECT price::text,approved_by,scope FROM public.contract_versions WHERE id=$1",[version])).rows[0];
  assert.equal(stored.price,"100.00");assert.equal(stored.approved_by,reviewer);assert.equal(stored.scope.scopeIncomplete,true);
  await expect("owner",vpath,409,{body:op("consume")});
  await expect("owner","/workspace/contracts/"+contract+"/versions/"+randomUUID(),409,{body:op("request",{versionId:randomUUID()})});
  await make(randomUUID(),record("contract_site",contract,unassigned,null),"owner",409);
  const job=randomUUID(),jobPath="/workspace/jobs/"+job;
  const create={action:"create",confirm:true,contractId:contract,siteId:site,serviceDate:"2026-11-15",evidenceDigest:hash("synthetic booking")};
  const event=(action,extra={})=>({action,confirm:true,eventId:randomUUID(),evidenceDigest:hash("synthetic job evidence"),...extra});
  await expect("owner",jobPath,403,{body:{...create,siteId:unassigned}});
  await expect("owner",jobPath,409,{body:{...create,serviceDate:"2026-12-01"}});
  await expect("reader",jobPath,403,{body:create});
  await expect("reviewer",jobPath,403,{tenant:other,body:create});
  const jobCreated=await expect("owner",jobPath,200,{body:create});
  assert.equal(jobCreated.status,"planned");assert.equal(jobCreated.readinessStatus,"not_ready");assert.equal(jobCreated.readiness.blockingCount,11);assert.equal(jobCreated.baselineId,version);
  await expect("owner",jobPath,409,{body:event("start")});
  await expect("owner",jobPath,400,{body:event("check",{checkId:"price",checkStatus:"not_applicable"})});
  for(const id of ["customer","site","scope","service_date","price","currency","access","materials","skills","permissions","completion_evidence"]){
   const r=await expect("owner",jobPath,200,{body:event("check",{checkId:id,checkStatus:"satisfied"})});
   assert.equal(r.safetyCertified,false);assert.equal(r.customerAcceptanceVerified,false);
  }
  const ready=await expect("reviewer",jobPath,200);assert.equal(ready.readinessStatus,"ready");assert.equal(ready.readiness.completenessPercent,100);
  const start=event("start");
  assert.equal((await expect("owner",jobPath,200,{body:start})).status,"in_progress");
  await expect("owner",jobPath,409,{body:start});
  await expect("owner",jobPath,409,{body:event("check",{checkId:"price",checkStatus:"missing"})});
  assert.equal((await expect("owner",jobPath,200,{body:event("complete")})).status,"completed");
  await expect("owner",jobPath,409,{body:event("cancel")});
  assert.equal((await expect("owner","/workspace/jobs",200)).items[0].jobId,job);
  assert.equal((await expect("reviewer","/workspace/jobs",200,{tenant:other})).items.length,0);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.workspace_jobs"),e=>e.code==="42501");
  await assert.rejects(()=>admin.query("DELETE FROM private.workspace_job_events WHERE tenant_id=$1 AND job_id=$2",[t,job]),e=>e.code==="55000");
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[t])).rows[0].ok,true);
  console.log("Managed job, shared readiness template, start gate and completion ledger passed");
 }finally{await new Promise(r=>api.close(r));await new Promise(r=>keys.close(r));await Promise.all([admin.end(),runtime.end()]);}
});
