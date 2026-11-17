import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomBytes,randomUUID} from "node:crypto";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

const enabled=Boolean(process.env.TEST_ADMIN_DATABASE_URL&&process.env.TEST_APP_DATABASE_URL);
test("independent payroll decisions, exact source reconciliation and maker-checker site allocation",{
 skip:!enabled
},async()=>{
 const tenantA="a1111111-1111-4111-8111-111111111111";
 const tenantB="a2222222-2222-4222-8222-222222222222";
 const importer="a3333333-3333-4333-8333-333333333333";
 const reviewer="a4444444-4444-4444-8444-444444444444";
 const owner="a5555555-5555-4555-8555-555555555555";
 const outside="a6666666-6666-4666-8666-666666666666";
 const businessA=randomUUID(),businessB=randomUUID(),siteA=randomUUID(),siteB=randomUUID();
 const issuer="https://profitpilot-ci.invalid/";
 const {publicKey,privateKey}=await generateKeyPair("RS256");
 const jwk=await exportJWK(publicKey);
 Object.assign(jwk,{kid:"profitpilot-payroll-workflow",use:"sig",alg:"RS256"});
 const jwks=createServer((req,res)=>{
  if(req.url!=="/.well-known/jwks.json"){res.writeHead(404).end();return;}
  res.writeHead(200,{"content-type":"application/json","cache-control":"no-store"});
  res.end(JSON.stringify({keys:[jwk]}));
 });
 await new Promise(resolve=>jwks.listen(0,"127.0.0.1",resolve));
 process.env.NODE_ENV="test";
 process.env.ENABLE_SYNTHETIC_PAYROLL_UI="true";
 process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
 process.env.AUTH_ISSUER=issuer;
 process.env.AUTH_AUDIENCE="profitpilot-api";
 process.env.AUTH_STEP_UP_ACR="urn:profitpilot:step-up";
 process.env.AUTH_JWKS_URL="http://127.0.0.1:"+jwks.address().port+"/.well-known/jwks.json";
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
 const {default:app}=await import("../server/index.js");
 const {pool:appPool}=await import("../server/db.js");
 const api=createServer(app);
 await new Promise(resolve=>api.listen(0,"127.0.0.1",resolve));
 const base="http://127.0.0.1:"+api.address().port;
 const ui=await fetch(base+"/dev/payroll");
 assert.equal(ui.status,200);
 assert.equal(ui.headers.get("cache-control"),"no-store");
 assert.match(await ui.text(),/SYNTHETIC DATA ONLY/);
 for(const asset of ["/dev/payroll.js","/dev/payroll.css","/dev/payroll-client.js"]){const response=await fetch(base+asset);assert.equal(response.status,200);assert.equal(response.headers.get("cache-control"),"no-store");}
 assert.equal((await fetch(base+"/dev/.env")).status,404);
 const {createPayrollClient}=await import("../src/payroll-client.js");
 const browserClient=subject=>createPayrollClient({getAccessToken:opts=>credential(subject,{mfa:opts.fresh}),fetchImpl:(route,opts)=>fetch(base+route,opts)});
 async function credential(subject,{mfa=true}={}){
  const now=Math.floor(Date.now()/1000);
  const claims={email:subject+"@example.invalid",auth_time:now,acr:"urn:profitpilot:step-up",amr:mfa?["pwd","mfa"]:["pwd"]};
  return new SignJWT(claims).setProtectedHeader({alg:"RS256",kid:jwk.kid})
   .setIssuer(issuer).setAudience("profitpilot-api").setSubject(subject)
   .setIssuedAt(now).setExpirationTime(now+300).setJti(randomBytes(16).toString("hex")).sign(privateKey);
 }
 async function send(method,path,subject,body,opts={}){
  const token=await credential(subject,opts);
  return fetch(base+path,{method,
   headers:{authorization:"Bearer "+token,...(body!==undefined?{"content-type":"application/json"}:{})},
   body:body===undefined?undefined:JSON.stringify(body)});
 }
 const path=tenant=>"/v1/tenants/"+tenant;
 try{
  await admin.query(
   "INSERT INTO tenants(id,legal_name) VALUES($1,'Payroll flow A'),($2,'Payroll flow B') ON CONFLICT(id) DO NOTHING",
   [tenantA,tenantB]);
  const identities=[
   [importer,"ci-payroll-importer"],
   [reviewer,"ci-payroll-reviewer"],
   [owner,"ci-payroll-owner"],
   [outside,"ci-payroll-outside"]
  ];
  for(const [id,subject] of identities)await admin.query(
   "INSERT INTO users(id,auth_subject,email,status,auth_issuer) VALUES($1,$2,$3,'active',$4) "+
   "ON CONFLICT(auth_subject) DO UPDATE SET status='active' ",
   [id,subject,subject+"@example.invalid",issuer]);
  for(const [tenant,user,role] of [
   [tenantA,importer,"analyst"],[tenantA,reviewer,"reviewer"],
   [tenantA,owner,"owner"],[tenantB,outside,"owner"]
  ])await admin.query(
   "INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES($1,$2,$3,'active') "+
   "ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=$3,status='active'",
   [tenant,user,role]);
  await admin.query(
   "INSERT INTO businesses(id,tenant_id,name) VALUES($1,$2,'Synthetic payroll business A'),($3,$4,'Synthetic payroll business B')",
   [businessA,tenantA,businessB,tenantB]);
  await admin.query(
   "INSERT INTO sites(id,tenant_id,business_id,name) VALUES($1,$2,$3,'Synthetic site A'),($4,$5,$6,'Synthetic site B')",
   [siteA,tenantA,businessA,siteB,tenantB,businessB]);

  const batchCreate=await send("POST",path(tenantA)+"/imports","ci-payroll-importer",{
   sourceType:"payroll",fileName:"synthetic-source.csv",sha256:randomBytes(32).toString("hex"),
   permissionReference:"SYNTHETIC CI TEST AUTHORIZATION",periodStart:"2026-02-01",periodEnd:"2026-02-14"
  });
  assert.equal(batchCreate.status,201);
  const batchId=(await batchCreate.json()).batch.id;
  const rows=[
   {source_ref:"SYNTHETIC-SOURCE-A",cost_component:"gross_wages",amount:"60.00",currency:"AUD",period_start:"2026-02-01",period_end:"2026-02-14"},
   {source_ref:"SYNTHETIC-SOURCE-B",cost_component:"gross_wages",amount:"40.00",currency:"AUD",period_start:"2026-02-01",period_end:"2026-02-14"},
   {source_ref:"SYNTHETIC-BAD-ROW",cost_component:"employer_cost",amount:"1e2",currency:"AUD",period_start:"2026-02-01",period_end:"2026-02-14"}
  ];
  assert.equal((await send("POST",path(tenantA)+"/imports/"+batchId+"/rows","ci-payroll-importer",{rows})).status,201);
  const validation=await send("POST",path(tenantA)+"/imports/"+batchId+"/validate","ci-payroll-importer",{});
  assert.equal(validation.status,200);
  assert.deepEqual([(await validation.json()).validCandidateRows], [2]);
  const page=await browserClient("ci-payroll-importer").review(tenantA,batchId);
  assert.equal(page.summary.total,3);
  assert.equal(page.summary.held,1);
  const rowPath=n=>path(tenantA)+"/imports/"+batchId+"/payroll/rows/"+n+"/decision";
  const approve={decision:"accepted",reason:"Independent validation of synthetic source row"};
  assert.equal((await send("POST",rowPath(1),"ci-payroll-importer",approve)).status,403,
   "import creator cannot approve source rows");
  assert.equal((await send("POST",rowPath(1),"ci-payroll-reviewer",approve,{mfa:false})).status,403,
   "fresh provider MFA required for financial source approval");
  assert.equal((await send("POST",rowPath(1),"ci-payroll-outside",approve)).status,403,
   "cross-tenant identity cannot approve rows");
  assert.equal((await browserClient("ci-payroll-reviewer").decide(tenantA,batchId,1,approve)).decision,"accepted");
  assert.equal((await send("POST",rowPath(2),"ci-payroll-reviewer",approve)).status,200);
  assert.equal((await send("POST",rowPath(3),"ci-payroll-reviewer",approve)).status,409,
   "structurally held source row cannot become accepted");
  assert.equal((await send("POST",rowPath(3),"ci-payroll-reviewer",{decision:"rejected",reason:"Unsupported amount notation"})).status,200);
  assert.equal((await send("POST",rowPath(2),"ci-payroll-reviewer",approve)).status,409,
   "accepted source rows are final");

  const poolPath=path(tenantA)+"/imports/"+batchId+"/payroll/pool";
  const poolBody={declaredTotal:"100.00",sourceReference:"SYNTHETIC-SOURCE-REPORT",reason:"Manually reconciled source-declared payroll total"};
  assert.equal((await send("POST",poolPath,"ci-payroll-importer",poolBody)).status,403,
   "importer cannot reconcile their own batch");
  assert.equal((await send("POST",poolPath,"ci-payroll-owner",poolBody,{mfa:false})).status,403,
   "fresh MFA required for pool reconciliation");
  assert.equal((await send("POST",poolPath,"ci-payroll-owner",{...poolBody,declaredTotal:"99.99"})).status,422,
   "declared source total must reconcile exactly in cents");
  const pool=await browserClient("ci-payroll-owner").reconcile(tenantA,batchId,poolBody);
  assert.equal(pool.totalAmount,"100.00");
  assert.equal(pool.externallyVerified,false);
  assert.equal(pool.acceptedRows,2);
  assert.equal(pool.rejectedRows,1);
  assert.equal((await send("POST",poolPath,"ci-payroll-owner",poolBody)).status,409,
   "one source pool per batch, no duplicate amount accounting");
  assert.equal((await send("POST",rowPath(1),"ci-payroll-reviewer",approve)).status,409,
   "closed source batch cannot be silently changed");
  assert.equal((await send("POST",path(tenantA)+"/imports/"+batchId+"/rows","ci-payroll-importer",{rows:[rows[0]]})).status,409,
   "accepted source batch must be closed to new rows");

  const draftPath=path(tenantA)+"/payroll/pools/"+pool.id+"/allocations";
  const lines=[
   {bucketType:"direct",siteId:siteA,amount:"60.00",sourceReference:"SYNTHETIC-DIRECT-EVIDENCE"},
   {bucketType:"approved_allocated",siteId:siteA,amount:"20.00",sourceReference:"SYNTHETIC-ALLOCATION-BASIS"},
   {bucketType:"non_site",amount:"10.00",sourceReference:"SYNTHETIC-NON-SITE"}
  ];
  const body={reason:"Synthetic evidence-led site allocation proposal",lines};
  assert.equal((await send("POST",draftPath,"ci-payroll-importer",{...body,lines:[{...lines[0],amount:"100.01"}]})).status,422,
   "allocated amount cannot exceed source pool");
  assert.equal((await send("POST",draftPath,"ci-payroll-importer",{...body,lines:[{...lines[0],siteId:siteB}]})).status,422,
   "foreign site references must be rejected without exposing data");
  const allocation=await browserClient("ci-payroll-importer").draft(tenantA,pool.id,body);
  assert.equal(allocation.status,"review");
  assert.deepEqual([allocation.direct,allocation.approvedAllocated,allocation.nonSite,allocation.unallocated],
   ["60.00","20.00","10.00","10.00"]);
  const detailPath=draftPath+"/"+allocation.id;
  const before=await admin.query(
   "SELECT COUNT(*)::int AS n FROM allocation_runs WHERE id=$1 AND status='confirmed'",
   [allocation.id]);
  assert.equal(before.rows[0].n,0,"draft must not enter confirmed financial calculations");
  const ownDetail=await browserClient("ci-payroll-reviewer").readAllocation(tenantA,pool.id,allocation.id);
  const serialized=JSON.stringify(ownDetail);
  for(const secret of ["SYNTHETIC-DIRECT-EVIDENCE","SYNTHETIC-NON-SITE","SYNTHETIC-SOURCE-A"])
   assert.equal(serialized.includes(secret),false,"approval view omits raw source references");
  assert.equal((await send("GET",path(tenantB)+"/payroll/pools/"+pool.id+"/allocations/"+allocation.id,"ci-payroll-outside")).status,404,
   "foreign tenant cannot read allocation by known object IDs");

  const confirmPath=detailPath+"/confirm";
  const confirmation={reason:"Independent MFA review confirmed all source bucket totals"};
  assert.equal((await send("POST",confirmPath,"ci-payroll-importer",confirmation)).status,403,
   "allocation maker cannot independently approve");
  assert.equal((await send("POST",confirmPath,"ci-payroll-reviewer",confirmation,{mfa:false})).status,403,
   "provider MFA required for cost confirmation");
  assert.equal((await send("POST",path(tenantB)+"/payroll/pools/"+pool.id+"/allocations/"+allocation.id+"/confirm","ci-payroll-outside",confirmation)).status,404,
   "foreign tenant cannot confirm a known object ID");
  const confirmed=await browserClient("ci-payroll-reviewer").confirm(tenantA,pool.id,allocation.id,{...confirmation,acknowledged:true});
  assert.equal(confirmed.status,"confirmed");
  assert.equal((await send("POST",confirmPath,"ci-payroll-reviewer",confirmation)).status,409);
  assert.equal((await send("POST",draftPath,"ci-payroll-importer",body)).status,409,
   "confirmed source pool cannot receive a second double-counted allocation");
  const amounts=await admin.query(
   "SELECT ar.status,ar.created_by,ar.reviewer_id,ar.direct_amount,ar.allocated_amount,ar.non_site_amount,"+
   "ar.excluded_amount,ar.residual_amount,p.total_amount "+
   "FROM allocation_runs ar JOIN payroll_pools p ON p.id=ar.payroll_pool_id WHERE ar.id=$1",
   [allocation.id]);
  assert.equal(amounts.rows[0].status,"confirmed");
  assert.equal(amounts.rows[0].created_by,importer);
  assert.equal(amounts.rows[0].reviewer_id,reviewer);
  assert.deepEqual([
   amounts.rows[0].direct_amount,amounts.rows[0].allocated_amount,amounts.rows[0].non_site_amount,
   amounts.rows[0].excluded_amount,amounts.rows[0].residual_amount,amounts.rows[0].total_amount
  ],["60.00","20.00","10.00","0.00","10.00","100.00"]);
  const siteCosts=await admin.query(
   "SELECT COALESCE(SUM(l.amount),0)::numeric(14,2) AS total FROM allocation_lines l "+
   "JOIN allocation_runs ar ON ar.id=l.allocation_run_id WHERE ar.id=$1 AND ar.status='confirmed' "+
   "AND l.site_id=$2 AND l.bucket_type IN ('direct','approved_allocated')",
   [allocation.id,siteA]);
  assert.equal(siteCosts.rows[0].total,"80.00");
  await assert.rejects(()=>admin.query("UPDATE allocation_runs SET status='review' WHERE id=$1",[allocation.id]),
   /immutable/i,"confirmed allocation runs are immutable even for a migration administrator");
  await assert.rejects(()=>admin.query("UPDATE allocation_lines SET amount=amount+1 WHERE allocation_run_id=$1",[allocation.id]),
   /immutable/i,"confirmed site lines are immutable");
  const auditState=await admin.query("SELECT * FROM private.verify_audit_chain($1)",[tenantA]);
  assert.equal(auditState.rows[0].is_valid,true,"payroll approvals preserve tamper-evident audit chain");
 }finally{
  await new Promise(resolve=>api.close(resolve));
  await appPool.end();
  await admin.end();
  await new Promise(resolve=>jwks.close(resolve));
 }
});
