import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import {createSecurityMonitor} from "./security-monitor.js";
import {sharedLimiter,startRateLimitRetention} from "./shared-rate-limit.js";
import {randomUUID,createHash} from "node:crypto";
import {withTenant,health,checkIdentitySession} from "./db.js";
import {validateProductionSecrets} from "./production-config.js";
import {MAX_BATCH_ROWS,createRequestAdmission,enforceJsonBudget} from "./request-budget.js";
import {proxyTrust,corsOrigins,createBoundedServer} from "./network-boundary.js";
validateProductionSecrets();
import {authRequired,requireRole,requireRecentMfa,sessionRequired} from "./auth.js";
import {quarantineConfig,sealQuarantine,MAX_QUARANTINE_BYTES} from "./quarantine.js";
const quarantine=quarantineConfig();
import {parseCsv,validateInvoiceRows,isIsoDate,money} from "../src/engine.js";

const app=express();
app.disable("x-powered-by");
app.set("trust proxy",proxyTrust());
const securityMonitor=createSecurityMonitor();
app.use(securityMonitor.middleware);
// Set privacy headers even for rejected or throttled requests.
app.use((req,res,next)=>{res.set("Cache-Control","no-store");res.set("Pragma","no-cache");next();});
app.use(helmet());
app.use(createRequestAdmission(32));
app.use(cors({origin:corsOrigins(),credentials:false,methods:["GET","POST"]}));
app.use(process.env.NODE_ENV==="production"?sharedLimiter({windowMs:60_000,limit:100,scope:"global"}):rateLimit({windowMs:60_000,limit:100,standardHeaders:true,legacyHeaders:false}));
// Production shares write counters across replicas; development uses local counters.
const mutationLimiter=process.env.NODE_ENV==="production"?sharedLimiter({windowMs:60_000,limit:60,scope:"write"}):rateLimit({windowMs:60_000,limit:60,standardHeaders:true,legacyHeaders:false,message:{error:"Too many write requests; retry later"}});
app.use("/v1/tenants/:tenantId",(req,res,next)=>req.method==="POST"?mutationLimiter(req,res,next):next());
app.get("/health",async(req,res)=>{try{await health();res.json({status:"ok",database:"connected"});}catch{res.status(503).json({status:"unavailable"});}});
app.use("/v1",authRequired());
app.use("/v1",sessionRequired(checkIdentitySession));
app.use("/v1",express.json({limit:"100kb",inflate:false}));
app.use("/v1",enforceJsonBudget);
const uuidPattern=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
for(const param of ["batchId","matchId","runId"])app.param(param,(req,res,next,value)=>uuidPattern.test(value)?next():res.status(400).json({error:"Invalid resource ID"}));
const requestTenant=(req,tenantId,fn)=>withTenant(tenantId,req.identity.subject,fn,req.identity);

async function membership(req,res,next){
 const tenantId=req.params.tenantId;
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(tenantId))return res.status(400).json({error:"Invalid tenant ID"});
 try{
  const admission=await requestTenant(req,tenantId,async client=>{
   const r=await client.query("SELECT role FROM tenant_memberships tm JOIN users u ON u.id=tm.user_id JOIN tenants t ON t.id=tm.tenant_id WHERE tm.tenant_id=$1 AND u.auth_subject=$2 AND tm.status='active' AND u.status='active' AND t.status='active'",[tenantId,req.identity.subject]);
   if(!r.rowCount)return null;
   const result=await client.query("SELECT private.admit_actor_request($1) AS retry",[tenantId]);
   const retry=result.rows[0]?.retry;
   if(!Number.isInteger(retry)||retry<0||retry>300)throw new Error("Invalid containment response");
   return {role:r.rows[0].role,retry};
  });
  if(!admission)return res.status(403).json({error:"No active membership for this tenant"});
  if(admission.retry){res.locals.actorContained=true;res.set("Retry-After",String(admission.retry));return res.status(429).json({error:"Temporary request restriction; retry later"});}
  req.membership={tenantId:tenantId.toLowerCase(),role:admission.role};next();
 }catch(e){next(e);}
}
app.get("/v1/me",async(req,res)=>{res.json({subject:req.identity.subject,email:req.identity.email,membershipsEndpoint:"Membership discovery is not exposed until a separately reviewed security-definer function is installed."});});
app.get("/v1/tenants/:tenantId/contracts",membership,async(req,res,next)=>{try{const rows=await requestTenant(req,req.membership.tenantId,async c=>(await c.query("SELECT id,customer_name,status FROM contracts WHERE tenant_id=$1 ORDER BY customer_name",[req.membership.tenantId])).rows);res.json({items:rows});}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/imports",membership,requireRole("owner","admin","analyst"),async(req,res,next)=>{
 try{
  const {sourceType,fileName,sha256,permissionReference,periodStart,periodEnd}=req.body||{};
  if(!["payroll","customer_invoice","supplier_invoice"].includes(sourceType)||typeof fileName!=="string"||!fileName.trim()||fileName.length>255||typeof sha256!=="string"||!/^[a-f0-9]{64}$/i.test(sha256)||typeof permissionReference!=="string"||permissionReference.length>256||!permissionReference.trim()||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart)return res.status(400).json({error:"Invalid import metadata"});
  const id=randomUUID();
  const result=await requestTenant(req,req.membership.tenantId,async c=>{
    const check=await c.query("SELECT private.import_reference_safe($1,255,true) AND private.import_reference_safe($2,256,false) AS safe",[fileName,permissionReference.trim()]);
    if(!check.rows[0].safe)return null;
    return c.query("INSERT INTO import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) SELECT $1,$2,$3,$4,$5,$6,'registered',$7,$8,u.id FROM users u WHERE u.auth_subject=$9 ON CONFLICT(tenant_id,file_sha256) DO NOTHING RETURNING id,status",[id,req.membership.tenantId,sourceType,periodStart,periodEnd,permissionReference.trim(),sha256.toLowerCase(),fileName,req.identity.subject]);
  });
  if(!result)return res.status(422).json({error:"Import metadata contains unsupported or potentially sensitive information; use an opaque business reference."});
  if(!result.rowCount){
   const old=await requestTenant(req,req.membership.tenantId,async c=>c.query("SELECT id,status,(source_type=$3 AND file_name=$4 AND source_period_start=$5::date AND source_period_end=$6::date AND permission_ref=$7) AS same_metadata FROM import_batches WHERE tenant_id=$1 AND file_sha256=$2",[req.membership.tenantId,sha256.toLowerCase(),sourceType,fileName,periodStart,periodEnd,permissionReference.trim()]));
   const existing=old.rows[0];
   if(!existing?.same_metadata)return res.status(409).json({error:"This file checksum is already registered with different import metadata. Reconcile the original registration; do not silently reuse it."});
   return res.status(200).json({batch:{id:existing.id,status:existing.status},idempotent:true});
  }
  res.status(201).json({batch:result.rows[0]});
 }catch(e){next(e);}
});
app.post("/v1/tenants/:tenantId/imports/:batchId/rows",membership,requireRole("owner","admin","analyst"),async(req,res,next)=>{try{
 const rows=req.body?.rows;
 const startRowNumber=req.body?.startRowNumber??1;
 if(!Number.isSafeInteger(startRowNumber)||startRowNumber<1||startRowNumber>1000000000||!Array.isArray(rows)||rows.length<1||rows.length>200||startRowNumber+rows.length-1>1000000000||rows.some(x=>!x||typeof x!=="object"||Array.isArray(x)))return res.status(400).json({error:"Provide 1–200 row objects and a valid positive startRowNumber"});
 const result=await requestTenant(req,req.membership.tenantId,async client=>{
  const batch=await client.query("SELECT id,status,source_type FROM import_batches WHERE id=$1 AND tenant_id=$2 FOR UPDATE",[req.params.batchId,req.membership.tenantId]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  if(!["registered","review","validating"].includes(batch.rows[0].status))return {status:409,error:"Import batch is not open for row ingestion"};
  if(batch.rows[0].source_type==="payroll")return {status:422,error:"Payroll row ingestion is disabled until the source-row ledger, privacy-safe column mapping and reviewer workflow are implemented. Do not submit employee or payroll personal information."};
  if((await client.query("SELECT private.quarantine_status($1,$2) AS pending",[req.membership.tenantId,req.params.batchId])).rows[0].pending)return {status:409,error:"Quarantined file is not approved for ingestion"};
  // Screen the entire chunk before persisting anything. Do not echo rejected values.
  const privacy=await client.query("SELECT bool_and(private.invoice_import_payload_safe(value)) AS safe FROM jsonb_array_elements($1::jsonb)",[JSON.stringify(rows)]);
  if(!privacy.rows[0].safe)return {status:422,error:"Invoice rows contain unsupported fields or potentially sensitive information. Use only approved business fields and opaque references."};
  // Preflight every row number before writing any row. A retry is idempotent
  // only when the persisted payload is byte-for-byte equivalent as JSON data.
  const args=[req.membership.tenantId,req.params.batchId,startRowNumber,JSON.stringify(rows)];
  const existing=await client.query("SELECT count(*) FILTER (WHERE r.payload IS DISTINCT FROM v.value)::int AS conflicts FROM jsonb_array_elements($4::jsonb) WITH ORDINALITY v(value,n) JOIN raw_import_rows r ON r.tenant_id=$1 AND r.batch_id=$2 AND r.row_number=$3::integer+v.n-1",args);
  if(existing.rows[0].conflicts)return {status:409,error:"A source row number already exists with different content. Register a corrected source version rather than overwriting import evidence."};
  const added=await client.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) SELECT $1,$2,($3::integer+v.n-1)::integer,v.value FROM jsonb_array_elements($4::jsonb) WITH ORDINALITY v(value,n) ON CONFLICT(batch_id,row_number) DO NOTHING RETURNING id",args);
  const inserted=added.rowCount;
  await client.query("UPDATE import_batches SET status='review' WHERE id=$1 AND tenant_id=$2",[req.params.batchId,req.membership.tenantId]);
  return {status:201,inserted,received:rows.length,duplicates:rows.length-inserted,startRowNumber};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(result.status).json({batchId:req.params.batchId,inserted:result.inserted,received:result.received,duplicates:result.duplicates,startRowNumber:result.startRowNumber});
 }catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/imports/:batchId/validate",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 const result=await requestTenant(req,req.membership.tenantId,async client=>{
  const batch=await client.query("SELECT id,status,source_type FROM import_batches WHERE id=$1 AND tenant_id=$2 FOR UPDATE",[req.params.batchId,req.membership.tenantId]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  if(!["registered","review","validating"].includes(batch.rows[0].status))return {status:409,error:"Import batch is closed for validation"};
  if(!["customer_invoice","supplier_invoice"].includes(batch.rows[0].source_type))return {status:422,error:"This validator currently supports invoice CSV rows only; payroll validation is not implemented."};
  const raw=await client.query("SELECT id,row_number,payload FROM raw_import_rows WHERE batch_id=$1 AND tenant_id=$2 ORDER BY row_number LIMIT $3",[req.params.batchId,req.membership.tenantId,MAX_BATCH_ROWS+1]);
  if(raw.rowCount>MAX_BATCH_ROWS)return {status:413,error:"Invoice batch exceeds validation capacity"};
  if(!raw.rowCount)return {status:422,error:"No persisted import rows found. Ingest rows before validation."};
  const checked=validateInvoiceRows(raw.rows.map(r=>({...r.payload,__rowNumber:String(r.row_number)})));
  let valid=0,held=0;
  const decisions=checked.map((item,i)=>{
   const decision=item.errors.length?"held":"candidate";
   if(decision==="held")held++;else valid++;
   return {raw_row_id:raw.rows[i].id,decision,reason:item.errors.join("; ")||"Structural validation passed; requires mapping and human review"};
  });
  await client.query("INSERT INTO mapping_decisions(tenant_id,raw_row_id,target_type,target_id,decision,confidence,method_version,reason) SELECT $1,v.raw_row_id,'invoice_row',NULL,v.decision,'LOW','invoice-validator-0.1.0',v.reason FROM jsonb_to_recordset($2::jsonb) AS v(raw_row_id uuid,decision text,reason text) ON CONFLICT(tenant_id,raw_row_id,method_version) DO UPDATE SET decision=EXCLUDED.decision,reason=EXCLUDED.reason",[req.membership.tenantId,JSON.stringify(decisions)]);
  await client.query("UPDATE import_batches SET status='review' WHERE id=$1 AND tenant_id=$2",[req.params.batchId,req.membership.tenantId]);
  return {status:200,batchId:req.params.batchId,total:raw.rowCount,validCandidateRows:valid,heldRows:held,automaticallyAccepted:0};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 const {status,...body}=result;res.status(status).json(body);
 }catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/matches/:matchId/decision",membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
 const {decision,reason}=req.body||{};
 if(!["confirmed","rejected","held"].includes(decision)||typeof reason!=="string"||reason.trim().length<3||reason.length>2000)return res.status(400).json({error:"Decision and reason are required"});
 const result=await requestTenant(req,req.membership.tenantId,async client=>{
  const user=await client.query("SELECT id FROM users WHERE auth_subject=$1",[req.identity.subject]);
  if(!user.rowCount)throw Object.assign(new Error("User identity is not provisioned in this tenant database"),{status:403});
  await client.query("SELECT set_config('app.audit_reason',$1,true)",[reason.trim()]);
  const updated=await client.query("UPDATE match_reviews SET decision=$1,reviewer_id=$2,reviewed_at=now() WHERE id=$3 AND tenant_id=$4 AND decision IN ('candidate','held') RETURNING id,decision,reviewed_at",[decision,user.rows[0].id,req.params.matchId,req.membership.tenantId]);
  if(!updated.rowCount)return null;
  // Migration 014 writes the audit event in the same transaction as the decision.
  return updated.rows[0];
 });
 if(!result)return res.status(404).json({error:"Review candidate not found or already finalised"});
 res.status(201).json({decision:result});
 }catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/calculations",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 const {contractId,siteId,periodStart,periodEnd}=req.body||{};
 if(typeof contractId!=="string"||!uuidPattern.test(contractId)||typeof siteId!=="string"||!uuidPattern.test(siteId)||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart)return res.status(400).json({error:"Valid contract, site and period are required"});
 const result=await requestTenant(req,req.membership.tenantId,async client=>{
  const base=await client.query("SELECT c.id,cv.version_no,cv.currency,cv.tax_basis FROM contracts c JOIN contract_versions cv ON cv.contract_id=c.id AND cv.tenant_id=c.tenant_id JOIN sites s ON s.id=$2 AND s.tenant_id=c.tenant_id AND s.business_id=c.business_id WHERE c.id=$1 AND c.tenant_id=$3 AND cv.approved_at IS NOT NULL AND cv.approved_by IS NOT NULL AND cv.effective_from <= $4::date AND (cv.effective_to IS NULL OR cv.effective_to >= $5::date)",[contractId,siteId,req.membership.tenantId,periodStart,periodEnd]);
  if(!base.rowCount)return {error:"No matching contract/site and effective contract version for this period"};
  if(base.rowCount!==1)return {error:"Overlapping contract versions make this period ambiguous. Correct the contract baseline before calculating."};
  const ledger=await client.query("SELECT to_regclass('public.allocation_lines') IS NOT NULL AS available");
  if(!ledger.rows[0].available)return {error:"Payroll source-row allocation ledger is not installed. No contribution calculation can be produced until the reviewed ledger migration is applied.",code:"PAYROLL_LEDGER_UNAVAILABLE"};
  const partialInvoicePeriods=await client.query("SELECT COUNT(*)::int AS count FROM match_reviews mr JOIN invoice_lines il ON il.id=mr.invoice_line_id AND il.tenant_id=mr.tenant_id JOIN invoices i ON i.id=il.invoice_id AND i.tenant_id=il.tenant_id WHERE mr.tenant_id=$1 AND mr.contract_id=$2 AND mr.site_id=$3 AND mr.decision='confirmed' AND i.direction='customer' AND mr.service_period_start <= $5::date AND mr.service_period_end >= $4::date AND NOT (mr.service_period_start >= $4::date AND mr.service_period_end <= $5::date)",[req.membership.tenantId,contractId,siteId,periodStart,periodEnd]);
  if(Number(partialInvoicePeriods.rows[0].count)>0)return {error:"A confirmed invoice service period overlaps only part of the requested calculation period. Align service periods before calculating; no pro-rata estimate is applied."};
  const revenue=await client.query("SELECT COALESCE(SUM(il.amount),0)::text AS amount,COUNT(*)::int AS line_count,COUNT(DISTINCT i.tax_basis)::int AS tax_basis_count,COUNT(DISTINCT i.currency)::int AS currency_count, BOOL_OR(i.tax_basis='unknown') AS unknown_tax_basis, MIN(i.currency) AS invoice_currency, MIN(i.tax_basis) AS invoice_tax_basis FROM match_reviews mr JOIN invoice_lines il ON il.id=mr.invoice_line_id AND il.tenant_id=mr.tenant_id JOIN invoices i ON i.id=il.invoice_id AND i.tenant_id=il.tenant_id WHERE mr.tenant_id=$1 AND mr.contract_id=$2 AND mr.site_id=$3 AND mr.decision='confirmed' AND i.direction='customer' AND mr.service_period_start <= $5::date AND mr.service_period_end >= $4::date AND mr.service_period_start IS NOT NULL AND mr.service_period_end IS NOT NULL",[req.membership.tenantId,contractId,siteId,periodStart,periodEnd]);
  const costs=await client.query("SELECT * FROM private.site_payroll_summary($1,$2,$3,$4)",[req.membership.tenantId,siteId,periodStart,periodEnd]);
  if(Number(costs.rows[0].partial_count)>0)return {error:"A confirmed payroll period overlaps only part of the requested service period. Align periods before calculating; no pro-rata estimate is applied."};
  if(!Number(revenue.rows[0].line_count)||!Number(costs.rows[0].line_count))return {error:"Insufficient evidence: confirmed invoice lines and confirmed site allocation lines are both required"};
  if(Number(costs.rows[0].currency_count)!==1||costs.rows[0].payroll_currency!==base.rows[0].currency)return {error:"Mixed or contract-mismatched payroll allocation currency. Resolve payroll source currency before calculating."};
  if(Number(revenue.rows[0].tax_basis_count)!==1||Number(revenue.rows[0].currency_count)!==1||revenue.rows[0].unknown_tax_basis||revenue.rows[0].invoice_currency!==base.rows[0].currency||base.rows[0].tax_basis==="unknown"||revenue.rows[0].invoice_tax_basis!==base.rows[0].tax_basis)return {error:"Mixed, unknown or contract-mismatched invoice tax/currency basis. Approve the contract tax basis and resolve source basis before calculating."};
  const parseCents=value=>{
   const text=String(value);
   if(!/^-?\d+(?:\.\d{1,2})?$/.test(text))throw new Error("Database returned a non-canonical monetary value");
   const negative=text.startsWith("-");
   const unsigned=negative?text.slice(1):text;
   const [whole,fraction=""]=unsigned.split(".");
   const cents=BigInt(whole)*100n+BigInt((fraction+"00").slice(0,2));
   return negative?-cents:cents;
  };
  const formatCents=value=>{
   const negative=value<0n,absolute=negative?-value:value;
   return (negative?"-":"")+String(absolute/100n)+"."+String(absolute%100n).padStart(2,"0");
  };
  const rev=parseCents(revenue.rows[0].amount),cost=parseCents(costs.rows[0].amount);
  const indicative=rev-cost;
  const outputs={revenue:formatCents(rev),deliveryCost:formatCents(cost),contribution:null,marginPercent:null,indicativeContribution:formatCents(indicative),currency:base.rows[0].currency,taxBasis:"consistent source invoice basis; no tax conversion applied",invoiceLineCount:Number(revenue.rows[0].line_count),allocationLineCount:Number(costs.rows[0].line_count),taxBasisCount:1,completeness:"incomplete",limitations:["Indicative contribution only; authoritative contribution and margin are withheld because the cost model is incomplete.","Management view only; not statutory or audited profit.","Only confirmed invoice matches and confirmed direct/approved site allocation lines are included.","Other delivery costs, non-site costs and unallocated payroll are excluded unless separately included in source records."]};
  const user=await client.query("SELECT id FROM users WHERE auth_subject=$1",[req.identity.subject]);if(!user.rowCount)throw Object.assign(new Error("User identity is not provisioned in this tenant database"),{status:403});
  const saved=await client.query("INSERT INTO calculation_runs(tenant_id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_by) VALUES($1,$2,$3,$4,$5,'0.1.0',$6,$7,'incomplete',$8) RETURNING id,created_at",[req.membership.tenantId,contractId,siteId,periodStart,periodEnd,JSON.stringify({contractVersion:base.rows[0].version_no,invoiceLineCount:outputs.invoiceLineCount,allocationLineCount:outputs.allocationLineCount}),JSON.stringify(outputs),user.rows[0].id]);
  return {id:saved.rows[0].id,createdAt:saved.rows[0].created_at,outputs};
 });
 if(result.error)return res.status(422).json({error:result.error,code:result.code||"CALCULATION_BLOCKED"});
 res.status(201).json(result);
 }catch(e){next(e);}});
 
app.get("/v1/tenants/:tenantId/calculations/:runId",membership,async(req,res,next)=>{try{
 const result=await requestTenant(req,req.membership.tenantId,client=>client.query("SELECT private.read_calculation_summary($1,$2) AS summary",[req.membership.tenantId,req.params.runId]));
 if(!result.rows[0]?.summary)return res.status(404).json({error:"Calculation run not found"});
 res.json(result.rows[0].summary);
 }catch(e){next(e);}});
 

// Raw CSV quarantine is opt-in for synthetic non-production testing only.
app.post("/v1/tenants/:tenantId/imports/:batchId/file",membership,requireRole("owner","admin"),requireRecentMfa,(req,res,next)=>{
 if(!quarantine)return res.status(503).json({error:"File upload is not enabled"});
 if(!req.is("text/csv"))return res.status(415).json({error:"Only uncompressed text/csv is supported"});
 next();
},express.raw({type:"text/csv",limit:MAX_QUARANTINE_BYTES,inflate:false}),async(req,res,next)=>{
 const tenant=req.membership.tenantId.toLowerCase(),batch=req.params.batchId.toLowerCase();
 let envelope;
 try{envelope=sealQuarantine(req.body,tenant,batch,quarantine);}
 catch{return res.status(400).json({error:"Invalid or unsupported CSV upload"});}
 finally{if(Buffer.isBuffer(req.body))req.body.fill(0);}
 try{
  const result=await requestTenant(req,tenant,async c=>(await c.query("SELECT private.quarantine_invoice_file($1,$2,$3,$4,$5,$6,$7) AS receipt",[tenant,batch,envelope.sha,envelope.keyId,envelope.nonce,envelope.tag,envelope.ciphertext])).rows[0].receipt);
  if(!result)return res.status(404).json({error:"Import batch not found"});
  res.status(201).json(result);
 }catch(e){
  if(e.code==="42501")return res.status(403).json({error:"Quarantine authority denied"});
  if(e.code==="23514")return res.status(422).json({error:"File checksum or import state does not match the registered batch"});
  if(e.code==="54000")return res.status(429).json({error:"Tenant quarantine capacity reached"});
  next(e);
 }
});

// Human approval never returns the file contents or marks rows financially accepted.
app.post("/v1/tenants/:tenantId/imports/:batchId/file/approve",membership,requireRole("owner","admin"),requireRecentMfa,async(req,res,next)=>{
 if(!quarantine)return res.status(503).json({error:"File processing is not enabled"});
 const batch=req.params.batchId.toLowerCase(),tenant=req.membership.tenantId;
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(batch)||Object.keys(req.body||{}).length!==0)return res.status(400).json({error:"Invalid approval request"});
 try{
  const approved=await requestTenant(req,tenant,async c=>(await c.query("SELECT private.approve_quarantine_promotion($1,$2) AS approved",[tenant,batch])).rows[0].approved);
  if(!approved)return res.status(404).json({error:"Import batch not found"});
  res.status(202).json({batchId:batch,status:"approved_for_processing"});
 }catch(e){
  if(e.code==="42501")return res.status(403).json({error:"Promotion authority denied"});
  if(e.code==="23514")return res.status(422).json({error:"File is not eligible for approved processing"});
  next(e);
 }
});

// A single, ephemeral, JSON summary; never an unrestricted database download.
app.post("/v1/tenants/:tenantId/calculations/:runId/export",membership,requireRole("owner","admin"),requireRecentMfa,async(req,res,next)=>{
 try{
  const runId=req.params.runId,purpose=req.body?.purpose;
  if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(runId)||!["internal_review","customer_reporting","accountant_review"].includes(purpose)||Object.keys(req.body||{}).length!==1)
    return res.status(400).json({error:"Valid calculation ID and approved export purpose required"});
  const result=await requestTenant(req,req.membership.tenantId,async client=>{
   const r=await client.query("SELECT private.export_calculation_summary($1,$2,$3) AS summary",[req.membership.tenantId,runId,purpose]);
   return r.rows[0]?.summary;
  });
  if(!result)return res.status(404).json({error:"Calculation run not found"});
  res.set("Content-Disposition",'attachment; filename="profitpilot-calculation.json"');
  res.set("X-Content-Type-Options","nosniff");
  res.json(result);
 }catch(e){if(e.code==="42501")return res.status(403).json({error:"Export authority denied"});next(e);}
});

app.use((err,req,res,next)=>{if(res.destroyed||res.writableEnded)return;if(res.headersSent)return next(err);const id=randomUUID();const status=err.code==="P4501"?429:err.code==="23505"?409:err.code==="54000"?413:err.code==="22P02"||err.code==="22P05"?400:err.status===503?503:(Number.isInteger(err.status)&&err.status>=400&&err.status<500?err.status:500);if(status===503)res.set("Retry-After","5");if(err.code==="P4501")res.set("Retry-After","3600");process.stderr.write(JSON.stringify({event:"request_error",id,code:typeof err.code==="string"?err.code:"INTERNAL",status})+"\n");res.status(status).json({error:err.code==="P4501"?"Financial access limit reached; retry later":status===409?"Conflicting record; refresh and review the current state":status<500?"Request could not be completed":status===503?"Request capacity temporarily unavailable":"Internal server error",reference:id});});
const port=Number(process.env.PORT||8080);
if(process.env.NODE_ENV==="production"){
 try{await health();}
 catch{process.stderr.write("Production database readiness checks failed; refusing to start.\n");await import("./db.js").then(m=>m.pool.end());process.exit(1);}
 startRateLimitRetention();securityMonitor.start();
}
if(process.env.NODE_ENV!=="test")createBoundedServer(app).listen(port,()=>process.stdout.write("ProfitPilot API listening on "+port+"\n"));
export default app;
