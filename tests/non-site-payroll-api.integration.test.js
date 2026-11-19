import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomUUID,createHash,randomBytes} from "node:crypto";
import {runQuarantineCycle} from "../scripts/quarantine-worker.js";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

test("confirmed non-site payroll exact allocation, correction and source receipt fences",{skip:!process.env.TEST_ADMIN_DATABASE_URL||!process.env.TEST_APP_DATABASE_URL,timeout:120000},async()=>{
 const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL,max:2});
 const t=randomUUID(),other=randomUUID(),owner=randomUUID(),reviewer=randomUUID(),analyst=randomUUID(),reader=randomUUID();
 const identities={owner,reviewer,analyst,reader};const subjects=Object.fromEntries(Object.entries(identities).map(([k,v])=>[k,"ci-sensitive-"+v]));
 const {publicKey,privateKey}=await generateKeyPair("RS256"),jwk=await exportJWK(publicKey);
 Object.assign(jwk,{kid:"ci-sensitive",alg:"RS256",use:"sig"});
 const keys=createServer((_req,res)=>{res.setHeader("Content-Type","application/json");res.end(JSON.stringify({keys:[jwk]}));});
 await new Promise(r=>keys.listen(0,"127.0.0.1",r));
 const keyId="ci-invoice-"+randomBytes(8).toString("hex"),secret=randomBytes(32).toString("hex");Object.assign(process.env,{QUARANTINE_UPLOADS_ENABLED:"true",QUARANTINE_KEY_ID:keyId,QUARANTINE_ENCRYPTION_KEY:secret});
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
  await admin.query("INSERT INTO public.tenants(id,legal_name) VALUES($1,'Synthetic invoice intake API'),($2,'Synthetic invoice other')",[t,other]);
  for(const [role,id] of Object.entries(identities))await admin.query("INSERT INTO public.users(id,auth_subject,email) VALUES($1,$2,$3)",[id,subjects[role],"old-"+role+"@example.invalid"]);
  for(const [role,id] of Object.entries(identities))await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,$3)",[t,id,role==="reader"?"read_only":role==="reviewer"?"admin":role]);
  await admin.query("INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES($1,$2,'admin')",[other,reviewer]);


  const business=randomUUID(),customer=randomUUID(),site=randomUUID(),unassigned=randomUUID(),contract=randomUUID(),link=randomUUID(),otherBusiness=randomUUID(),foreignSite=randomUUID();
  const record=(kind,parentId,relatedId,label)=>({confirm:true,kind,parentId,relatedId,label});
  const path=id=>"/workspace/records/"+id,make=(id,input,role="owner",status=201,tenant=t)=>expect(role,path(id),status,{body:input,tenant});
  await make(business,record("business",null,null,"Synthetic business"));
  await make(otherBusiness,record("business",null,null,"Synthetic foreign business"),"reviewer",201,other);
  await make(foreignSite,record("site",otherBusiness,null,"Synthetic foreign site"),"reviewer",201,other);
  await make(customer,record("customer",business,null,"Synthetic customer"));
  await make(site,record("site",business,null,"Synthetic site"));
  await make(unassigned,record("site",business,null,"Synthetic unassigned site"));
  await make(contract,record("contract",business,customer,"Synthetic contract"));
  await make(link,record("contract_site",contract,site,null));
  const listed=await expect("owner","/workspace/records-by-kind/contract",200);
  assert.deepEqual(listed.items,[{id:contract,kind:"contract",parentId:business,relatedId:customer,label:"Synthetic contract"}]);assert.equal(listed.nextCursor,null);
  assert.equal((await expect("reviewer","/workspace/records-by-kind/contract",200,{tenant:other})).items.length,0);
  await expect("reader","/workspace/records-by-kind/contract",403);
   const site2=randomUUID();
   await make(site2,record("site",business,null,"Synthetic second site"));
   await make(randomUUID(),record("contract_site",contract,site2,null));
  const order=randomUUID(),version=randomUUID(),vpath="/workspace/contracts/"+contract+"/versions/"+order;
  const terms={versionId:version,periodStart:"2026-11-01",periodEnd:"2026-11-30",price:"100.00",taxBasis:"gst_exclusive",billingBasis:"monthly",evidenceDigest:hash("synthetic contract evidence")};
  const op=(step,change={})=>({confirm:true,step,...terms,...change});
  assert.equal((await expect("owner",vpath,200,{body:op("request")})).status,"requested");
  assert.equal((await expect("reviewer",vpath,200)).price,"100.00");
  assert.equal((await expect("reviewer",vpath,200,{body:op("approve")})).status,"approved_pending_record");
  assert.equal((await admin.query("SELECT count(*)::int n FROM public.contract_versions WHERE tenant_id=$1 AND contract_id=$2",[t,contract])).rows[0].n,0);
  assert.equal((await expect("owner",vpath,200,{body:op("consume")})).status,"approved_baseline");
  const stored=(await admin.query("SELECT price::text,approved_by,scope FROM public.contract_versions WHERE id=$1",[version])).rows[0];
  assert.equal(stored.price,"100.00");assert.equal(stored.approved_by,reviewer);assert.equal(stored.scope.scopeIncomplete,true);

  const scanner=await admin.connect();
  try{
   await scanner.query("SET ROLE profitpilot_scanner");
   const columns=["invoice_id","site","date","amount","customer_id","contract_id","site_id","service_period_start","service_period_end","currency","tax_basis"];
   const row=(cash,day="2026-11-15",sid=site,tax="gst_exclusive")=>["INV-REVIEW-A","Synthetic site",day,cash,customer,contract,sid,"2026-11-01","2026-11-14","AUD",tax].join(",");
   const bytes=Buffer.from(columns.join(",")+"\n"+row("0.10")+"\n"+row("0.20")+"\n");
   const sha=hash(bytes);
   const registration=await expect("owner","/imports",201,{body:{sourceType:"customer_invoice",fileName:"synthetic-invoice.csv",sha256:sha,permissionReference:"reviewed-invoice-authority",periodStart:"2026-11-01",periodEnd:"2026-11-14"}});
   const batch=registration.batch.id,orderId=randomUUID(),path="/invoice-intakes/"+batch+"/orders/"+orderId;
   const controls={controlTotal:"0.30",rowCount:2,evidenceDigest:hash("independent source controls")};
   const upload=await fetch(base+"/v1/tenants/"+t+"/imports/"+batch+"/file",{method:"POST",headers:{authorization:"Bearer "+await auth("owner"),"content-type":"text/csv"},body:bytes});
   assert.equal(upload.status,201,await upload.clone().text());
   const cfg={keyId,secret,scan:async()=> "clean",limit:1};
   assert.equal((await runQuarantineCycle(scanner,cfg)).contentValidated,1);
   await expect("owner","/imports/"+batch+"/file/approve",202,{body:{}});
   assert.equal((await runQuarantineCycle(scanner,cfg)).promoted,1);
   const preview=await expect("owner",path+"/preview",200,{body:controls});
   assert.equal(preview.invoiceCount,1);assert.equal(preview.lines.length,2);assert.equal(preview.lines[0].baselineId,version);assert.equal(preview.fileSha256,sha);
   assert.equal(preview.controlTotal,"0.30");
   const action=(step,change={})=>({...controls,scopeDigest:preview.scopeDigest,confirm:true,step,...change});
   assert.equal((await expect("owner",path,200,{body:action("request")})).status,"requested");
   assert.equal((await expect("reviewer",path,200,{body:action("approve")})).status,"approved_pending_record");
   assert.equal((await admin.query("SELECT count(*)::int n FROM public.invoices WHERE tenant_id=$1",[t])).rows[0].n,0);
   assert.equal((await expect("owner",path,200,{body:action("consume")})).status,"accepted");
   const fact=(await admin.query("SELECT id,total_amount::text FROM public.invoices WHERE tenant_id=$1",[t])).rows;
   assert.equal(fact.length,1);assert.equal(fact[0].total_amount,"0.30");
   const links=(await admin.query("SELECT i.line_id,i.match_id,m.decision,m.reviewer_id,m.site_id,i.raw_row_id FROM private.invoice_intake_lines i JOIN public.match_reviews m ON m.id=i.match_id WHERE i.tenant_id=$1 AND i.batch_id=$2",[t,batch])).rows;
   assert.equal(links.length,2);assert.ok(links.every(x=>x.decision==="confirmed"&&x.reviewer_id===reviewer&&x.site_id===site));
   assert.equal((await expect("reviewer",path,200)).status,"accepted");
   await assert.rejects(()=>admin.query("UPDATE public.invoices SET total_amount=1 WHERE id=$1",[fact[0].id]),e=>e.code==="55000");
   await assert.rejects(()=>admin.query("UPDATE public.raw_import_rows SET payload='{}' WHERE id=$1",[links[0].raw_row_id]),e=>e.code==="55000");
   await assert.rejects(()=>admin.query("INSERT INTO public.invoice_lines(tenant_id,invoice_id,line_number,description,amount) VALUES($1,$2,999,'Synthetic duplicate',1)",[t,fact[0].id]),e=>e.code==="55000");
   await assert.rejects(()=>admin.query("INSERT INTO public.match_reviews(tenant_id,invoice_line_id,confidence,decision) VALUES($1,$2,'HIGH','confirmed')",[t,links[0].line_id]),e=>e.code==="55000");
   await assert.rejects(()=>runtime.query("SELECT * FROM private.invoice_intake_receipts"),e=>e.code==="42501");
   assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[t])).rows[0].ok,true);
   // Complete the same managed site/period through the actual reviewed payroll
   // APIs: no seeded invoice facts, allocation rows or calculation outputs.
   const rows=[{source_row_key:"ppr_"+hash("workflow site cost"),amount:"0.10",currency:"AUD"},{source_row_key:"ppr_"+hash("workflow non-site cost"),amount:"0.20",currency:"AUD"}];
   const payrollHash=hash("source_row_key,amount,currency\n"+rows.map(r=>r.source_row_key+","+r.amount+",AUD\n").join(""));
   const payroll=await expect("owner","/imports",201,{body:{sourceType:"payroll",fileName:"minimized-payroll-v1.csv",sha256:payrollHash,permissionReference:"reviewed-payroll-authority",periodStart:"2026-11-01",periodEnd:"2026-11-14"}});
   const poolId=randomUUID(),payrollPath="/payroll/intakes/"+payroll.batch.id+"/orders/"+randomUUID();
   const payrollInput={poolId,sourceNamespace:randomUUID(),controlTotal:"0.30",rowCount:2,authorityDigest:hash("workflow authority"),policyDigest:hash("workflow allocation policy"),controlDigest:hash("workflow control"),rows};
   const payrollPreview=await expect("owner",payrollPath+"/preview",200,{body:payrollInput});
   const payrollStep=step=>({...payrollInput,scopeDigest:payrollPreview.scopeDigest,confirm:true,step});
   assert.equal((await expect("owner",payrollPath,200,{body:payrollStep("request")})).status,"requested");
   assert.equal((await expect("reviewer",payrollPath,200,{body:payrollStep("approve")})).status,"approved");
   assert.equal((await expect("owner",payrollPath,200,{body:payrollStep("consume")})).status,"source-accepted");
   const calc={contractId:contract,siteId:site,periodStart:"2026-11-01",periodEnd:"2026-11-14"};
   const allocationPath="/payroll/pools/"+poolId+"/allocations/"+randomUUID();
   const allocation=await expect("owner",allocationPath,200,{body:{confirm:true,lines:[
    {sourceRowKey:rows[0].source_row_key,bucket:"approved_allocated",siteId:site,amount:"0.10",evidenceRef:"ev_"+hash("workflow site allocation").slice(0,60)},
    {sourceRowKey:rows[1].source_row_key,bucket:"non_site",siteId:null,amount:"0.20",evidenceRef:"ev_"+hash("workflow non-site allocation").slice(0,60)}
   ]}});
   assert.equal(allocation.residual,"0.00");assert.equal(allocation.allocationConfirmed,false);
   const confirmPath="/payroll/proposals/"+allocation.proposalId+"/confirm",confirmation={confirm:true,evidenceDigest:allocation.evidenceDigest};
   assert.equal((await expect("reviewer",confirmPath,200,{body:confirmation})).status,"confirmed");
   const payLine=(await admin.query("SELECT a.id FROM public.allocation_lines a JOIN public.allocation_runs r ON r.tenant_id=a.tenant_id AND r.id=a.allocation_run_id WHERE a.tenant_id=$1 AND a.site_id=$2 AND r.status='confirmed'",[t,site])).rows[0].id;
   const pp="/shared-costs/payroll/"+payLine+"/orders/"+randomUUID(),pb={shares:[[contract,version,"0.10"]],evidenceDigest:hash("payroll share"),confirm:true};
   for(const [role,step] of [["owner","request"],["reviewer","approve"],["owner","consume"]])await expect(role,pp,200,{body:{...pb,step}});

   const request={...calc,useNonSitePayroll:true};
   const blocked=await expect("owner","/calculations",422,{body:request});assert.equal(blocked.code,"NON_SITE_PAYROLL_ALLOCATION_REQUIRED");
   const source=(await admin.query("SELECT a.id FROM public.allocation_lines a JOIN public.allocation_runs r ON r.tenant_id=a.tenant_id AND r.id=a.allocation_run_id WHERE a.tenant_id=$1 AND a.site_id IS NULL AND a.bucket_type='non_site' AND r.status='confirmed'",[t])).rows[0].id;
   const shares=[[site,contract,version,"0.07"],[site2,contract,version,"0.08"]].sort((a,b)=>a[0]<b[0]?-1:1);shares.push([null,null,null,"0.05"]);
   const nonSitePath="/shared-costs/non_site_payroll/"+source+"/orders/"+randomUUID(),input={shares,evidenceDigest:hash("reviewed non-site assignment"),confirm:true};
   await expect("owner",nonSitePath,409,{body:{...input,shares:[[site,contract,version,"0.19"]],step:"request"}});
   await expect("owner",nonSitePath,403,{body:{...input,shares:[[foreignSite,contract,version,"0.20"]],step:"request"}});
   await expect("reader",nonSitePath,403,{body:{...input,step:"request"}});
   assert.equal((await expect("owner",nonSitePath,200,{body:{...input,step:"request"}})).status,"requested");
   await expect("owner",nonSitePath,403,{body:{...input,step:"approve"}});
   await expect("reviewer",nonSitePath,200,{body:{...input,step:"approve"}});
   const recorded=await expect("owner",nonSitePath,200,{body:{...input,step:"consume"}});assert.equal(recorded.status,"allocated");assert.equal(recorded.source.kind,"non_site_payroll");assert.equal(recorded.source.amount,"0.20");assert.deepEqual(recorded.shares,shares);
   const d=await expect("owner","/financial-coverage",200,{body:calc});assert.equal(d.nonSitePayroll.cost,"0.07");assert.equal(d.nonSitePayroll.unallocatedCost,"0.05");assert.equal(d.nonSitePayroll.missingCount,0);assert.equal(d.canAttemptNonSiteCalculation,true);
   const net=await expect("owner","/calculations",201,{body:request});assert.equal(net.outputs.payrollCost,"0.10");assert.equal(net.outputs.nonSitePayrollCost,"0.07");assert.equal(net.outputs.deliveryCost,"0.17");assert.equal(net.outputs.indicativeContribution,"0.13");assert.equal(net.outputs.unallocatedNonSitePayroll,"0.05");assert.equal(net.outputs.contribution,null);
   const report=await expect("owner","/calculations/"+net.id,200);assert.equal(report.formula_version,"0.8.0");assert.equal(report.sourceTrace.format,"profitpilot-source-trace-v7");
   const out=await expect("owner","/calculations/"+net.id+"/export",200,{body:{purpose:"internal_review"}});assert.deepEqual(out.sourceTrace,report.sourceTrace);
   const cp="/shared-costs/non_site_payroll/"+source+"/orders/"+randomUUID(),updated=[[site,contract,version,"0.08"],[site2,contract,version,"0.07"]].sort((a,b)=>a[0]<b[0]?-1:1);updated.push([null,null,null,"0.05"]);
   const revised={...input,shares:updated,replacesOrderId:recorded.orderId,evidenceDigest:hash("reviewed non-site correction")};
   for(const [role,step] of [["owner","request"],["reviewer","approve"],["owner","consume"]])await expect(role,cp,200,{body:{...revised,step}});
   await expect("owner","/calculations/"+net.id,409);await expect("owner","/calculations/"+net.id+"/export",409,{body:{purpose:"internal_review"}});
   const fresh=await expect("owner","/calculations",201,{body:request});assert.equal(fresh.outputs.nonSitePayrollCost,"0.08");assert.equal(fresh.outputs.deliveryCost,"0.18");assert.equal(fresh.outputs.indicativeContribution,"0.12");
   assert.equal((await admin.query("SELECT snapshot_digest FROM private.calculation_source_receipts WHERE calculation_id=$1",[net.id])).rows[0].snapshot_digest,report.sourceTrace.digest);
   assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[t])).rows[0].ok,true);
   console.log("Non-site payroll source exact conservation, tenant and independent review fences, correction and minimized report verified");
  }finally{scanner.release();}
 }finally{await new Promise(r=>api.close(r));await new Promise(r=>keys.close(r));await Promise.all([admin.end(),runtime.end()]);}
});
