import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomUUID,createHash} from "node:crypto";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

test("actual authenticated sensitive API: payroll review, own verified account correction, one-time scoped disposal",{skip:!process.env.TEST_ADMIN_DATABASE_URL||!process.env.TEST_APP_DATABASE_URL,timeout:60000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:2});
 const t=randomUUID(),other=randomUUID(),owner=randomUUID(),reviewer=randomUUID(),analyst=randomUUID(),reader=randomUUID(),business=randomUUID(),site=randomUUID(),batch=randomUUID(),pool=randomUUID(),raw=randomUUID(),source=randomUUID(),run=randomUUID(),disposal=randomUUID(),order=randomUUID();
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
  await admin.query("INSERT INTO public.tenants(id,legal_name) VALUES($1,'Synthetic sensitive API'),($2,'Synthetic sensitive other')",[t,other]);
  for(const [role,id] of Object.entries(identities))await admin.query("INSERT INTO public.users(id,auth_subject,email) VALUES($1,$2,$3)",[id,subjects[role],"old-"+role+"@example.invalid"]);
  for(const [role,id] of Object.entries(identities))await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,$3)",[t,id,role==="reader"?"read_only":role==="reviewer"?"admin":role]);
  await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,'admin')",[other,reviewer]);
  await admin.query("INSERT INTO public.businesses(id,tenant_id,name) VALUES($1,$2,'Synthetic business')",[business,t]);
  await admin.query("INSERT INTO public.sites(id,tenant_id,business_id,name) VALUES($1,$2,$3,'Synthetic site')",[site,t,business]);
  await admin.query("INSERT INTO public.import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,$2,'payroll','2026-11-01','2026-11-14','Synthetic authority','accepted',$3,'synthetic.csv',$4)",[batch,t,hash(batch),owner]);
  await admin.query("INSERT INTO public.raw_import_rows(id,tenant_id,batch_id,row_number,payload) VALUES($1,$2,$3,1,$4)",[raw,t,batch,{source_row_key:"row-a",amount:"0.30",currency:"AUD"}]);
  await admin.query("INSERT INTO public.payroll_pools(id,tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref) VALUES($1,$2,$3,'2026-11-01','2026-11-14',0.30,'AUD','source-a')",[pool,t,batch]);
  await admin.query("INSERT INTO public.payroll_source_rows(id,tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency) VALUES($1,$2,$3,$4,'row-a',$5,0.30,'AUD')",[source,t,pool,raw,hash("row-a\n0.30\nAUD")]);
  await admin.query("INSERT INTO public.allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,residual_amount) VALUES($1,$2,$3,'synthetic-v1','review',0.30,0)",[run,t,pool]);
  await admin.query("INSERT INTO public.allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id) VALUES($1,$2,$3,'direct',0.30,'evidence-a',$4)",[t,run,site,source]);
  const submitPath="/payroll/runs/"+run+"/submit";
  await expect("reader",submitPath,403,{body:{submit:true}});
  await expect("analyst",submitPath,403,{body:{submit:true},claims:{amr:["pwd"]}});
  const proposal=await expect("owner",submitPath,200,{body:{submit:true}});
  assert.equal(proposal.total,"0.30");assert.equal(proposal.status,"pending_review");
  const reviewPath="/payroll/proposals/"+proposal.proposalId;
  await expect("reviewer",reviewPath,403,{tenant:other});await expect("reader",reviewPath,403);
  assert.equal((await expect("reviewer",reviewPath,200)).evidenceDigest,proposal.evidenceDigest);
  const confirm={confirm:true,evidenceDigest:proposal.evidenceDigest};
  await expect("owner",reviewPath+"/confirm",403,{body:confirm});
  await expect("reviewer",reviewPath+"/confirm",403,{body:{...confirm,evidenceDigest:"e".repeat(64)}});
  const confirmed=await expect("reviewer",reviewPath+"/confirm",200,{body:confirm});
  assert.equal(confirmed.status,"confirmed");await expect("reviewer",reviewPath+"/confirm",409,{body:confirm});
  // Account access is self-only, and correction requires the current verified
  // issuer email, never a user-supplied replacement or cross-tenant target.
  const privacy="/privacy/account";
  const own=await expect("reader",privacy,200);assert.equal(own.accountId,reader);assert.equal(own.email,"old-reader@example.invalid");
  await expect("reader",privacy+"?accountId="+owner,400);
  await expect("reader",privacy,403,{tenant:other});await expect("reader",privacy,403,{claims:{amr:["pwd"]}});
  const correction=privacy+"/correct-email";
  await expect("reader",correction,400,{body:{confirm:true,email:"wrong@example.invalid"}});
  await expect("reader",correction,403,{body:{confirm:true},claims:{email_verified:false}});
  assert.equal((await expect("reader",correction,200,{body:{confirm:true}})).email,"verified-reader@example.invalid");
  await expect("reader",correction,403,{body:{confirm:true},claims:{email:"stale@example.invalid"}});
  assert.equal((await admin.query("SELECT email FROM public.users WHERE id=$1",[reader])).rows[0].email,"verified-reader@example.invalid");

  // Privacy requests are status-only; evidence is kept in an approved
  // assisted process. No arbitrary target or third-party data is disclosed.
  const caseId=randomUUID(),casePath="/privacy/cases/"+caseId;
  const requestCase={action:"request",kind:"access",confirm:true};
  const opened=await expect("reader",casePath,200,{body:requestCase});
  assert.equal(opened.status,"received");assert.equal(opened.kind,"access");
  assert.ok(opened.internalReviewTarget);assert.equal(opened.escalationDue,false);
  await expect("reader",casePath,409,{body:requestCase});
  await expect("analyst",casePath,403);
  await expect("reviewer",casePath,403,{tenant:other});
  await expect("reader",casePath,403,{body:{action:"acknowledge",confirm:true}});
  await expect("owner",casePath,403,{body:{action:"resolve",reasonCode:"fulfilled",evidenceDigest:hash("synthetic-response"),confirm:true}});
  assert.equal((await expect("owner",casePath,200,{body:{action:"acknowledge",confirm:true}})).status,"acknowledged");
  assert.equal((await expect("owner",casePath,200,{body:{action:"resolve",reasonCode:"fulfilled",evidenceDigest:hash("synthetic-response"),confirm:true}})).status,"resolved");
  const resultCase=await expect("reader",casePath,200);
  assert.equal(resultCase.status,"resolved");assert.equal(resultCase.reasonCode,"fulfilled");
  assert.ok(!Object.hasOwn(resultCase,"evidenceDigest")&&!Object.hasOwn(resultCase,"openedBy"));
  await expect("owner",casePath,409,{body:{action:"resolve",reasonCode:"fulfilled",evidenceDigest:hash("other"),confirm:true}});
  const staffPath="/privacy/cases/"+randomUUID();
  assert.equal((await expect("owner",staffPath,200,{body:{action:"intake",kind:"correction",evidenceDigest:hash("verified-assisted-intake"),confirm:true}})).status,"received");
  await expect("reader",staffPath,403);
  await expect("owner",staffPath,200,{body:{action:"acknowledge",confirm:true}});
  await expect("owner",staffPath,403,{body:{action:"refuse",reasonCode:"identity_not_verified",evidenceDigest:hash("synthetic-refusal"),confirm:true}});
  assert.equal((await expect("reviewer",staffPath,200,{body:{action:"refuse",reasonCode:"identity_not_verified",evidenceDigest:hash("synthetic-refusal"),confirm:true}})).status,"refused");
  await assert.rejects(()=>runtime.query("SELECT * FROM private.privacy_rights_cases"),e=>e.code==="42501");
  // A short-lived, two-person grant executes one exact admitted operation.
  await admin.query("INSERT INTO public.import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) VALUES($1,$2,'customer_invoice','2026-11-01','2026-11-14','Synthetic authority','rejected',$3,'synthetic.csv',$4)",[disposal,t,hash(disposal),owner]);
  await admin.query("INSERT INTO public.raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,1,$3)",[t,disposal,{invoice_id:"INV-1"}]);
  await admin.query("SELECT private.approve_import_disposal($1,$2,clock_timestamp()-interval '1 day','CI_SCOPE_APPROVAL')",[t,disposal]);
  const prefix="/privacy/invoices/"+disposal;
  const {scopeDigest}=await expect("owner",prefix+"/disposal-preview",200,{body:{}});
  const path=prefix+"/disposals/"+order,step=(step)=>({step,scopeDigest,confirm:true});
  await expect("owner",path,403,{body:step("consume")});
  await expect("owner",path,200,{body:step("request")});
  await expect("owner",path,403,{body:step("approve")});await expect("analyst",path,403,{body:step("approve")});
  await expect("reviewer",path,403,{tenant:other,body:step("approve")});
  await expect("reviewer",path,200,{body:step("approve")});
  await expect("reviewer",path,403,{body:step("consume")});
  const removed=await expect("owner",path,200,{body:step("consume")});assert.equal(removed.removedRows,1);
  await expect("owner",path,403,{body:step("consume")});
  assert.equal((await admin.query("SELECT count(*)::int AS n FROM private.import_disposal_tombstones WHERE tenant_id=$1 AND batch_id=$2",[t,disposal])).rows[0].n,1);
  assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[t])).rows[0].ok,true);
  await assert.rejects(()=>runtime.query("SELECT * FROM private.account_correction_nonces"),e=>e.code==="42501");
  await assert.rejects(()=>runtime.query("SELECT private.payroll_api_summary($1,$2)",[t,proposal.proposalId]),e=>e.code==="42501");
 }finally{await new Promise(r=>api.close(r));await new Promise(r=>keys.close(r));await Promise.all([admin.end(),runtime.end()]);}
});
