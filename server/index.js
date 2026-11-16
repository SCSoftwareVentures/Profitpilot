import "dotenv/config";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import {randomUUID,createHash} from "node:crypto";
import {withTenant,health} from "./db.js";
import {authRequired,requireRole} from "./auth.js";
import {parseCsv,validateInvoiceRows,isIsoDate,money} from "../src/engine.js";

const app=express();
app.disable("x-powered-by");
app.use(helmet());
app.use(cors({origin:(process.env.CORS_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean),credentials:false,methods:["GET","POST"]}));
app.use(rateLimit({windowMs:60_000,limit:100,standardHeaders:true,legacyHeaders:false}));
app.use(express.json({limit:"100kb"}));
app.get("/health",async(req,res)=>{try{await health();res.json({status:"ok",database:"connected"});}catch{res.status(503).json({status:"unavailable"});}});
app.use("/v1",authRequired());

async function membership(req,res,next){
 const tenantId=req.params.tenantId;
 if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(tenantId))return res.status(400).json({error:"Invalid tenant ID"});
 try{
  const r=await withTenant(tenantId,req.identity.subject,client=>client.query("SELECT role FROM tenant_memberships tm JOIN users u ON u.id=tm.user_id JOIN tenants t ON t.id=tm.tenant_id WHERE tm.tenant_id=$1 AND u.auth_subject=$2 AND tm.status='active' AND u.status='active' AND t.status='active'",[tenantId,req.identity.subject]));
  if(!r.rowCount)return res.status(403).json({error:"No active membership for this tenant"});
  req.membership={tenantId,role:r.rows[0].role};next();
 }catch(e){next(e);}
}
app.get("/v1/me",async(req,res)=>{res.json({subject:req.identity.subject,email:req.identity.email,membershipsEndpoint:"Membership discovery is not exposed until a separately reviewed security-definer function is installed."});});
app.get("/v1/tenants/:tenantId/contracts",membership,async(req,res,next)=>{try{const rows=await withTenant(req.membership.tenantId,req.identity.subject,async c=>(await c.query("SELECT id,customer_name,status FROM contracts WHERE tenant_id=$1 ORDER BY customer_name",[req.membership.tenantId])).rows);res.json({items:rows});}catch(e){next(e);}});
app.post("/v1/tenants/:tenantId/imports",membership,requireRole("owner","admin","analyst"),async(req,res,next)=>{
 try{
  const {sourceType,fileName,sha256,permissionReference,periodStart,periodEnd}=req.body||{};
  if(!["payroll","customer_invoice","supplier_invoice"].includes(sourceType)||typeof fileName!=="string"||fileName.length>255||!/^[a-f0-9]{64}$/i.test(sha256||"")||typeof permissionReference!=="string"||!permissionReference.trim()||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart)return res.status(400).json({error:"Invalid import metadata"});
  const id=randomUUID();
  const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>c.query("INSERT INTO import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by) SELECT $1,$2,$3,$4,$5,$6,'registered',$7,$8,u.id FROM users u WHERE u.auth_subject=$9 ON CONFLICT(tenant_id,file_sha256) DO NOTHING RETURNING id,status",[id,req.membership.tenantId,sourceType,periodStart,periodEnd,permissionReference.trim(),sha256.toLowerCase(),fileName,req.identity.subject]));
  if(!result.rowCount){
   const old=await withTenant(req.membership.tenantId,req.identity.subject,async c=>c.query("SELECT id,status,(source_type=$3 AND file_name=$4 AND source_period_start=$5::date AND source_period_end=$6::date AND permission_ref=$7) AS same_metadata FROM import_batches WHERE tenant_id=$1 AND file_sha256=$2",[req.membership.tenantId,sha256.toLowerCase(),sourceType,fileName,periodStart,periodEnd,permissionReference.trim()]));
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
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const batch=await client.query("SELECT id,status,source_type FROM import_batches WHERE id=$1 AND tenant_id=$2 FOR UPDATE",[req.params.batchId,req.membership.tenantId]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  if(!["registered","review","validating"].includes(batch.rows[0].status))return {status:409,error:"Import batch is not open for row ingestion"};
  if(batch.rows[0].source_type==="payroll")return {status:422,error:"Payroll row ingestion is disabled until the source-row ledger, privacy-safe column mapping and reviewer workflow are implemented. Do not submit employee or payroll personal information."};
  // Preflight every row number before writing any row. A retry is idempotent
  // only when the persisted payload is byte-for-byte equivalent as JSON data.
  for(let i=0;i<rows.length;i++){
   const existing=await client.query("SELECT payload = $4::jsonb AS same FROM raw_import_rows WHERE tenant_id=$1 AND batch_id=$2 AND row_number=$3",[req.membership.tenantId,req.params.batchId,startRowNumber+i,JSON.stringify(rows[i])]);
   if(existing.rowCount&&!existing.rows[0].same)
    return {status:409,error:"A source row number already exists with different content. Register a corrected source version rather than overwriting import evidence."};
  }
  let inserted=0;
  for(let i=0;i<rows.length;i++){
   const row=await client.query("INSERT INTO raw_import_rows(tenant_id,batch_id,row_number,payload) VALUES($1,$2,$3,$4) ON CONFLICT(batch_id,row_number) DO NOTHING RETURNING id",[req.membership.tenantId,req.params.batchId,startRowNumber+i,JSON.stringify(rows[i])]);
   inserted+=row.rowCount;
  }
  await client.query("UPDATE import_batches SET status='review' WHERE id=$1 AND tenant_id=$2",[req.params.batchId,req.membership.tenantId]);
  return {status:201,inserted,received:rows.length,duplicates:rows.length-inserted,startRowNumber};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 res.status(result.status).json({batchId:req.params.batchId,inserted:result.inserted,received:result.received,duplicates:result.duplicates,startRowNumber:result.startRowNumber});
 }catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/imports/:batchId/validate",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const batch=await client.query("SELECT id,status,source_type FROM import_batches WHERE id=$1 AND tenant_id=$2",[req.params.batchId,req.membership.tenantId]);
  if(!batch.rowCount)return {status:404,error:"Import batch not found"};
  if(!["customer_invoice","supplier_invoice"].includes(batch.rows[0].source_type))return {status:422,error:"This validator currently supports invoice CSV rows only; payroll validation is not implemented."};
  const raw=await client.query("SELECT id,row_number,payload FROM raw_import_rows WHERE batch_id=$1 AND tenant_id=$2 ORDER BY row_number",[req.params.batchId,req.membership.tenantId]);
  if(!raw.rowCount)return {status:422,error:"No persisted import rows found. Ingest rows before validation."};
  const checked=validateInvoiceRows(raw.rows.map(r=>({...r.payload,__rowNumber:String(r.row_number)})));
  let valid=0,held=0;
  for(let i=0;i<raw.rows.length;i++){
   const item=checked[i],row=raw.rows[i],decision=item.errors.length?"held":"candidate";
   if(decision==="held")held++;else valid++;
   await client.query("INSERT INTO mapping_decisions(tenant_id,raw_row_id,target_type,target_id,decision,confidence,method_version,reason) VALUES($1,$2,'invoice_row',NULL,$3,'LOW','invoice-validator-0.1.0',$4) ON CONFLICT(tenant_id,raw_row_id,method_version) DO UPDATE SET decision=EXCLUDED.decision,reason=EXCLUDED.reason",[req.membership.tenantId,row.id,decision,item.errors.join("; ")||"Structural validation passed; requires mapping and human review"]);
  }
  await client.query("UPDATE import_batches SET status='review' WHERE id=$1 AND tenant_id=$2",[req.params.batchId,req.membership.tenantId]);
  return {status:200,batchId:req.params.batchId,total:raw.rowCount,validCandidateRows:valid,heldRows:held,automaticallyAccepted:0};
 });
 if(result.error)return res.status(result.status).json({error:result.error});
 const {status,...body}=result;res.status(status).json(body);
 }catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/matches/:matchId/decision",membership,requireRole("owner","admin","reviewer"),async(req,res,next)=>{try{
 const {decision,reason}=req.body||{};
 if(!["confirmed","rejected","held"].includes(decision)||typeof reason!=="string"||reason.trim().length<3||reason.length>2000)return res.status(400).json({error:"Decision and reason are required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const user=await client.query("SELECT id FROM users WHERE auth_subject=$1",[req.identity.subject]);
  if(!user.rowCount)throw Object.assign(new Error("User identity is not provisioned in this tenant database"),{status:403});
  const updated=await client.query("UPDATE match_reviews SET decision=$1,reviewer_id=$2,reviewed_at=now() WHERE id=$3 AND tenant_id=$4 AND decision IN ('candidate','held') RETURNING id,decision,reviewed_at",[decision,user.rows[0].id,req.params.matchId,req.membership.tenantId]);
  if(!updated.rowCount)return null;
  await client.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata) VALUES($1,$2,'invoice_match_decision','match_review',$3,$4,$5)",[req.membership.tenantId,user.rows[0].id,req.params.matchId,reason.trim(),JSON.stringify({decision})]);
  return updated.rows[0];
 });
 if(!result)return res.status(404).json({error:"Review candidate not found or already finalised"});
 res.status(201).json({decision:result});
 }catch(e){next(e);}});

app.post("/v1/tenants/:tenantId/calculations",membership,requireRole("owner","admin","analyst","reviewer"),async(req,res,next)=>{try{
 const {contractId,siteId,periodStart,periodEnd}=req.body||{};
 if(!/^[0-9a-f-]{36}$/i.test(contractId||"")||!/^[0-9a-f-]{36}$/i.test(siteId||"")||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart)return res.status(400).json({error:"Valid contract, site and period are required"});
 const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
  const base=await client.query("SELECT c.id,cv.version_no,cv.currency,cv.tax_basis FROM contracts c JOIN contract_versions cv ON cv.contract_id=c.id AND cv.tenant_id=c.tenant_id JOIN sites s ON s.id=$2 AND s.tenant_id=c.tenant_id AND s.business_id=c.business_id WHERE c.id=$1 AND c.tenant_id=$3 AND cv.approved_at IS NOT NULL AND cv.approved_by IS NOT NULL AND cv.effective_from <= $4::date AND (cv.effective_to IS NULL OR cv.effective_to >= $5::date)",[contractId,siteId,req.membership.tenantId,periodStart,periodEnd]);
  if(!base.rowCount)return {error:"No matching contract/site and effective contract version for this period"};
  if(base.rowCount!==1)return {error:"Overlapping contract versions make this period ambiguous. Correct the contract baseline before calculating."};
  const ledger=await client.query("SELECT to_regclass('public.allocation_lines') IS NOT NULL AS available");
  if(!ledger.rows[0].available)return {error:"Payroll source-row allocation ledger is not installed. No contribution calculation can be produced until the reviewed ledger migration is applied.",code:"PAYROLL_LEDGER_UNAVAILABLE"};
  const partialInvoicePeriods=await client.query("SELECT COUNT(*)::int AS count FROM match_reviews mr JOIN invoice_lines il ON il.id=mr.invoice_line_id AND il.tenant_id=mr.tenant_id JOIN invoices i ON i.id=il.invoice_id AND i.tenant_id=il.tenant_id WHERE mr.tenant_id=$1 AND mr.contract_id=$2 AND mr.site_id=$3 AND mr.decision='confirmed' AND i.direction='customer' AND mr.service_period_start <= $5::date AND mr.service_period_end >= $4::date AND NOT (mr.service_period_start >= $4::date AND mr.service_period_end <= $5::date)",[req.membership.tenantId,contractId,siteId,periodStart,periodEnd]);
  if(Number(partialInvoicePeriods.rows[0].count)>0)return {error:"A confirmed invoice service period overlaps only part of the requested calculation period. Align service periods before calculating; no pro-rata estimate is applied."};
  const revenue=await client.query("SELECT COALESCE(SUM(il.amount),0)::text AS amount,COUNT(*)::int AS line_count,COUNT(DISTINCT i.tax_basis)::int AS tax_basis_count,COUNT(DISTINCT i.currency)::int AS currency_count, BOOL_OR(i.tax_basis='unknown') AS unknown_tax_basis, MIN(i.currency) AS invoice_currency, MIN(i.tax_basis) AS invoice_tax_basis FROM match_reviews mr JOIN invoice_lines il ON il.id=mr.invoice_line_id AND il.tenant_id=mr.tenant_id JOIN invoices i ON i.id=il.invoice_id AND i.tenant_id=il.tenant_id WHERE mr.tenant_id=$1 AND mr.contract_id=$2 AND mr.site_id=$3 AND mr.decision='confirmed' AND i.direction='customer' AND mr.service_period_start <= $5::date AND mr.service_period_end >= $4::date AND mr.service_period_start IS NOT NULL AND mr.service_period_end IS NOT NULL",[req.membership.tenantId,contractId,siteId,periodStart,periodEnd]);
  const partialPeriods=await client.query("SELECT COUNT(*)::int AS count FROM allocation_runs ar JOIN payroll_pools pp ON pp.id=ar.payroll_pool_id AND pp.tenant_id=ar.tenant_id JOIN allocation_lines al ON al.allocation_run_id=ar.id AND al.tenant_id=ar.tenant_id WHERE ar.tenant_id=$1 AND al.site_id=$4 AND ar.status='confirmed' AND pp.period_start <= $3::date AND pp.period_end >= $2::date AND NOT (pp.period_start >= $2::date AND pp.period_end <= $3::date)",[req.membership.tenantId,periodStart,periodEnd,siteId]);
  if(Number(partialPeriods.rows[0].count)>0)return {error:"A confirmed payroll period overlaps only part of the requested service period. Align periods before calculating; no pro-rata estimate is applied."};
  const costs=await client.query("SELECT COALESCE(SUM(al.amount),0)::numeric(14,2) AS amount,COUNT(*)::int AS line_count FROM allocation_lines al JOIN allocation_runs ar ON ar.id=al.allocation_run_id AND ar.tenant_id=al.tenant_id JOIN payroll_pools pp ON pp.id=ar.payroll_pool_id AND pp.tenant_id=ar.tenant_id WHERE al.tenant_id=$1 AND al.site_id=$2 AND al.bucket_type IN ('direct','approved_allocated') AND ar.status='confirmed' AND pp.period_start >= $3::date AND pp.period_end <= $4::date",[req.membership.tenantId,siteId,periodStart,periodEnd]);
  if(!Number(revenue.rows[0].line_count)||!Number(costs.rows[0].line_count))return {error:"Insufficient evidence: confirmed invoice lines and confirmed site allocation lines are both required"};
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
  await client.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata) VALUES($1,$2,'calculation_created','calculation_run',$3,'Versioned management contribution calculation',$4)",[req.membership.tenantId,user.rows[0].id,saved.rows[0].id,JSON.stringify({formulaVersion:"0.1.0",periodStart,periodEnd})]);
  return {id:saved.rows[0].id,createdAt:saved.rows[0].created_at,outputs};
 });
 if(result.error)return res.status(422).json({error:result.error,code:result.code||"CALCULATION_BLOCKED"});
 res.status(201).json(result);
 }catch(e){next(e);}});
 
app.get("/v1/tenants/:tenantId/calculations/:runId",membership,async(req,res,next)=>{try{
 const result=await withTenant(req.membership.tenantId,req.identity.subject,client=>client.query("SELECT id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_at FROM calculation_runs WHERE id=$1 AND tenant_id=$2",[req.params.runId,req.membership.tenantId]));
 if(!result.rowCount)return res.status(404).json({error:"Calculation run not found"});
 res.json(result.rows[0]);
 }catch(e){next(e);}});
 

app.use((err,req,res,next)=>{const id=randomUUID();const status=err.code==="23505"?409:(Number.isInteger(err.status)&&err.status>=400&&err.status<500?err.status:500);process.stderr.write(JSON.stringify({event:"request_error",id,code:typeof err.code==="string"?err.code:"INTERNAL",status})+"\n");res.status(status).json({error:status===409?"Conflicting record; refresh and review the current state":status<500?"Request could not be completed":"Internal server error",reference:id});});
const port=Number(process.env.PORT||8080);
if(process.env.NODE_ENV!=="test")app.listen(port,()=>process.stdout.write("ProfitPilot API listening on "+port+"\n"));
export default app;
