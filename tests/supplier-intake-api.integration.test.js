import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {randomUUID,createHash,randomBytes} from "node:crypto";
import {runQuarantineCycle} from "../scripts/quarantine-worker.js";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

test("scanned supplier costs independently reviewed and kept separate from revenue",{skip:!process.env.TEST_ADMIN_DATABASE_URL||!process.env.TEST_APP_DATABASE_URL,timeout:90000},async()=>{
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

  const scanner=await admin.connect();
  try{
   await scanner.query("SET ROLE profitpilot_scanner");
   const columns=["invoice_id","site","date","amount","customer_id","contract_id","site_id","service_period_start","service_period_end","currency","tax_basis"];
   const values=(ref,cash,day="2026-11-15",sid=site,tax="gst_exclusive")=>[ref,"Synthetic site",day,cash,customer,contract,sid,"2026-11-01","2026-11-14","AUD",tax].join(",");
   const cfg={keyId,secret,scan:async()=> "clean",limit:1};
   async function stage(sourceType,rows){
    const bytes=Buffer.from(columns.join(",")+"\n"+rows.join("\n")+"\n"),sha256=hash(bytes);
    const registration=await expect("owner","/imports",201,{body:{sourceType,fileName:"synthetic-invoice.csv",sha256,permissionReference:"reviewed-invoice-authority",periodStart:"2026-11-01",periodEnd:"2026-11-14"}});
    const batch=registration.batch.id,path="/invoice-intakes/"+batch+"/orders/"+randomUUID();
    const upload=await fetch(base+"/v1/tenants/"+t+"/imports/"+batch+"/file",{method:"POST",headers:{authorization:"Bearer "+await auth("owner"),"content-type":"text/csv"},body:bytes});
    assert.equal(upload.status,201,await upload.clone().text());
    assert.equal((await runQuarantineCycle(scanner,cfg)).contentValidated,1);
    await expect("owner","/imports/"+batch+"/file/approve",202,{body:{}});
    assert.equal((await runQuarantineCycle(scanner,cfg)).promoted,1);
    return {batch,path};
   }
   const supplier=await stage("supplier_invoice",[values("SUPPLIER-A", "0.10"),values("SUPPLIER-A","0.20")]);
   const controls={controlTotal:"0.30",rowCount:2,evidenceDigest:hash("supplier source proof")};
   const preview=await expect("owner",supplier.path+"/preview",200,{body:controls});
   assert.equal(preview.sourceType,"supplier_invoice");assert.equal(preview.costClassification,"direct_site_candidate");assert.equal(preview.supplierIdentityVerified,false);assert.equal(preview.controlTotal,"0.30");
   assert.equal(preview.lines[0].baselineId,version);assert.equal(preview.lines[0].customerId,customer);
   const action=(step,change={})=>({...controls,scopeDigest:preview.scopeDigest,confirm:true,step,...change});
   await expect("owner",supplier.path+"/preview",409,{body:{...controls,controlTotal:"0.31"}});
   await expect("reader",supplier.path+"/preview",403,{body:controls});
   await expect("owner",supplier.path+"/preview",403,{body:controls,claims:{amr:["pwd"]}});
   await expect("reviewer",supplier.path+"/preview",403,{tenant:other,body:controls});
   await expect("owner",supplier.path,403,{body:action("consume")});
   await expect("owner",supplier.path,200,{body:action("request")});
   await expect("owner",supplier.path,403,{body:action("approve")});
   await expect("reviewer",supplier.path,403,{body:action("approve",{scopeDigest:hash("direction substitution")})});
   await expect("reviewer",supplier.path,200,{body:action("approve")});
   await expect("reviewer",supplier.path,403,{body:action("consume")});
   const accepted=await expect("owner",supplier.path,200,{body:action("consume")});
   assert.equal(accepted.status,"accepted");assert.equal(accepted.costClassification,"direct_site_candidate");
   const invoices=(await admin.query("SELECT id,direction,total_amount::text FROM public.invoices WHERE tenant_id=$1",[t])).rows;
   assert.equal(invoices.length,1);assert.equal(invoices[0].direction,"supplier");assert.equal(invoices[0].total_amount,"0.30");
   const lines=(await admin.query("SELECT m.evidence,m.decision,m.reviewer_id,m.contract_id,m.site_id FROM private.invoice_intake_lines l JOIN public.match_reviews m ON m.id=l.match_id WHERE l.tenant_id=$1 AND l.batch_id=$2",[t,supplier.batch])).rows;
   assert.equal(lines.length,2);for(const line of lines){assert.equal(line.evidence.costClassification,"direct_site_candidate");assert.equal(line.evidence.supplierIdentityVerified,false);assert.equal(line.decision,"confirmed");assert.equal(line.reviewer_id,reviewer);assert.equal(line.contract_id,contract);assert.equal(line.site_id,site);}
   await assert.rejects(()=>admin.query("UPDATE public.invoices SET direction='customer' WHERE id=$1",[invoices[0].id]),e=>e.code==="55000");
   await expect("owner",supplier.path,409,{body:action("consume")});
   const calc={contractId:contract,siteId:site,periodStart:"2026-11-01",periodEnd:"2026-11-14"};
   await expect("owner","/calculations",422,{body:calc});
   const duplicate=await stage("supplier_invoice",[values("supplier-a","0.11")]);
   await expect("owner",duplicate.path+"/preview",409,{body:{controlTotal:"0.11",rowCount:1,evidenceDigest:hash("duplicate") }});
   assert.equal((await admin.query("SELECT count(*)::int n FROM public.invoices WHERE tenant_id=$1 AND direction='customer'",[t])).rows[0].n,0);
   assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[t])).rows[0].ok,true);
   const cp="/supplier-costs/"+supplier.batch+"/orders/"+randomUUID();
   const input={intakeScopeDigest:preview.scopeDigest,classification:"direct_site",evidenceDigest:hash("reviewed no overlap evidence"),confirm:true};
   const act=(step,patch={})=>({...input,step,...patch});
   await expect("reader",cp,403,{body:act("request")});
   await expect("owner",cp,403,{body:act("request"),claims:{amr:["pwd"]}});
   await expect("reviewer",cp,403,{tenant:other,body:act("request")});
   await expect("owner",cp,403,{body:act("request",{intakeScopeDigest:hash("wrong source")})});
   assert.equal((await expect("owner",cp,200,{body:act("request")})).status,"requested");
   await expect("owner",cp,403,{body:act("approve")});
   await expect("reviewer",cp,403,{body:act("approve",{classification:"payroll_overlap"})});
   assert.equal((await expect("reviewer",cp,200,{body:act("approve")})).status,"approved_pending_record");
   await expect("reviewer",cp,403,{body:act("consume")});
   const classified=await expect("owner",cp,200,{body:act("consume")});
   assert.equal(classified.status,"classified");assert.equal(classified.classification,"direct_site");assert.equal(classified.includedInCalculation,false);assert.equal(classified.paymentAuthorized,false);
   assert.deepEqual(await expect("reviewer",cp,200),classified);
   await expect("owner",cp,409,{body:act("consume")});
   await expect("owner","/supplier-costs/"+supplier.batch+"/orders/"+randomUUID(),409,{body:act("request")});
   await assert.rejects(()=>runtime.query("SELECT * FROM private.supplier_cost_receipts"),e=>e.code==="42501");
   await assert.rejects(()=>admin.query("DELETE FROM private.supplier_cost_receipts WHERE tenant_id=$1",[t]),e=>e.code==="55000");
   assert.equal((await admin.query("SELECT private.verify_audit_chain($1) AS ok",[t])).rows[0].ok,true);
   console.log("Reviewed supplier direction, exact direct site candidate mapping, authorization, duplicate denial and immutable materialization passed; independent cost disposition passed");
  }finally{scanner.release();}
 }finally{await new Promise(r=>api.close(r));await new Promise(r=>keys.close(r));await Promise.all([admin.end(),runtime.end()]);}
});
