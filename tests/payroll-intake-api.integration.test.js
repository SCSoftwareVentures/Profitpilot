import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomUUID,createHash,generateKeyPairSync} from "node:crypto";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

test("authenticated minimized payroll intake reconciles and persists only after independent approval",{skip:!process.env.TEST_ADMIN_DATABASE_URL||!process.env.TEST_APP_DATABASE_URL,timeout:60000},async()=>{
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
  const screen=await fetch(base+"/candidate/security/");
  assert.equal(screen.status,200);assert.match(screen.headers.get("cache-control"),/no-store/);assert.match(screen.headers.get("content-security-policy"),/script-src 'self'/);
  assert.match(await screen.text(),/Non-production, synthetic records only/);
  const script=await fetch(base+"/candidate/security/app.js");assert.equal(script.status,200);assert.match(await script.text(),/credentials:"omit"/);
  await admin.query("INSERT INTO public.tenants(id,legal_name) VALUES($1,'Synthetic payroll intake API'),($2,'Synthetic payroll intake other')",[t,other]);
  for(const [role,id] of Object.entries(identities))await admin.query("INSERT INTO public.users(id,auth_subject,email) VALUES($1,$2,$3)",[id,subjects[role],"old-"+role+"@example.invalid"]);
  for(const [role,id] of Object.entries(identities))await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,$3)",[t,id,role==="reader"?"read_only":role==="reviewer"?"admin":role]);
  await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,'admin')",[other,reviewer]);

  const sourceRows=[{source_row_key:"ppr_"+hash("synthetic a"),amount:"0.10",currency:"AUD"},{source_row_key:"ppr_"+hash("synthetic b"),amount:"0.20",currency:"AUD"}];
  const fileHash=hash("source_row_key,amount,currency\n"+sourceRows.map(r=>r.source_row_key+","+r.amount+",AUD\n").join(""));
  const meta={sourceType:"payroll",fileName:"minimized-payroll-v1.csv",sha256:fileHash,permissionReference:"reviewed-payroll-authority",periodStart:"2026-11-01",periodEnd:"2026-11-14"};
  const registration=await expect("owner","/imports",201,{body:meta}),batch=registration.batch.id,order=randomUUID(),poolId=randomUUID(),sourceNamespace=randomUUID();
  const path="/payroll/intakes/"+batch+"/orders/"+order;
  const input={poolId,sourceNamespace,controlTotal:"0.30",rowCount:2,authorityDigest:hash("authority"),policyDigest:hash("policy"),controlDigest:hash("control"),rows:sourceRows};
  await expect("owner","/imports/"+batch+"/rows",422,{body:{rows:sourceRows}});
  await expect("reader",path+"/preview",403,{body:input});
  await expect("analyst",path+"/preview",403,{body:input});
  await expect("owner",path+"/preview",403,{body:input,claims:{amr:["pwd"]}});
  await expect("reviewer",path+"/preview",409,{tenant:other,body:input});
  await expect("owner",path+"/preview",400,{body:{...input,rows:[{...sourceRows[0],name:"synthetic"},sourceRows[1]]}});
  await expect("owner",path+"/preview",400,{body:{...input,controlTotal:"0.31"}});
  await expect("owner",path+"/preview",400,{body:{...input,rows:[sourceRows[0],sourceRows[0]],controlTotal:"0.20"}});
  await expect("owner",path+"/preview",409,{body:{...input,rows:[sourceRows[1],sourceRows[0]]}});
  const preview=await expect("owner",path+"/preview",200,{body:input});
  assert.equal(preview.fileSha256,fileHash);assert.equal(preview.controlTotal,"0.30");assert.equal(preview.periodStart,"2026-11-01");
  assert.equal(preview.allocationConfirmed,false);assert.ok(!Object.hasOwn(preview,"rows"));
  const op=(step,changes={})=>({...input,scopeDigest:preview.scopeDigest,confirm:true,step,...changes});
  await expect("owner",path,403,{body:op("consume")});
  await expect("owner",path,403,{body:op("request",{scopeDigest:hash("forged")})});
  assert.equal((await expect("owner",path,200,{body:op("request")})).status,"requested");
  await expect("owner",path,403,{body:op("approve")});
  await expect("reviewer",path,403,{body:op("approve",{policyDigest:hash("substitution")})});
  assert.equal((await expect("reviewer",path,200,{body:op("approve")})).status,"approved");
  assert.equal((await admin.query("SELECT count(*)::int n FROM public.raw_import_rows WHERE tenant_id=$1 AND batch_id=$2",[t,batch])).rows[0].n,0);
  await expect("reviewer",path,403,{body:op("consume")});
  const accepted=await expect("owner",path,200,{body:op("consume")});
  assert.equal(accepted.status,"source-accepted");assert.equal(accepted.allocationConfirmed,false);assert.equal(accepted.controlTotal,"0.30");assert.equal(accepted.rowCount,2);
  assert.equal((await expect("reviewer",path,200)).status,"source-accepted");
  await expect("reader",path,403);await expect("reviewer",path,403,{tenant:other});
  await expect("owner",path,409,{body:op("consume")});
  const summary=(await admin.query("SELECT count(*)::int n,sum(amount)::text total FROM public.payroll_source_rows WHERE tenant_id=$1 AND payroll_pool_id=$2",[t,poolId])).rows[0];assert.deepEqual(summary,{n:2,total:"0.30"});
  assert.equal((await admin.query("SELECT count(*)::int n FROM public.allocation_runs WHERE tenant_id=$1 AND payroll_pool_id=$2",[t,poolId])).rows[0].n,0);
  for(const table of ["payroll_intake_requests","payroll_intake_receipts"])await assert.rejects(()=>runtime.query("SELECT * FROM private."+table),e=>e.code==="42501");
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[t])).rows[0].ok,true);
  console.log("Authenticated minimized payroll intake reconciled and independently accepted exact source rows");
 }finally{await new Promise(r=>api.close(r));await new Promise(r=>keys.close(r));await Promise.all([admin.end(),runtime.end()]);}
});
