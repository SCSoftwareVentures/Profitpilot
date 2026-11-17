// Human-controlled payroll source reconciliation and allocation workflow.
// Only synthetic evidence until production identity, privacy and legal gates are met.
import {randomUUID} from "node:crypto";
import {withTenant} from "./db.js";
import {requirePermission,requireStepUp} from "./auth.js";
import {validatePayrollRows} from "../src/engine.js";

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const DECIMAL=/^(0|[1-9][0-9]{0,11})(?:\.([0-9]{1,2}))?$/;
const BUCKETS=new Set(["direct","approved_allocated","non_site","excluded"]);
const error=(status,message)=>({status,error:message});
const validReason=s=>typeof s==="string"&&s.trim().length>=3&&s.trim().length<=1000;
const textRef=s=>typeof s==="string"&&s.trim().length>=3&&s.trim().length<=120;
function cents(input){
 const match=typeof input==="string"?DECIMAL.exec(input):null;
 if(!match)return null;
 return BigInt(match[1])*100n+BigInt((match[2]||"").padEnd(2,"0"));
}
function money(value){
 const x=BigInt(value);
 return (x/100n).toString()+"."+(x%100n).toString().padStart(2,"0");
}
async function audit(client,member,action,type,id,reason,metadata={}){
 await client.query(
  "INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata) VALUES($1,$2,$3,$4,$5,$6,$7)",
  [member.tenantId,member.userId,action,type,id,reason,JSON.stringify(metadata)]);
}
function respond(res,result,success=200){
 if(result.error)return res.status(result.status).json({error:result.error});
 return res.status(success).json(result);
}
function checkId(req,res,key){
 if(UUID.test(req.params[key]||""))return true;
 res.status(400).json({error:"Invalid resource ID"});
 return false;
}
export function registerPayrollRoutes(app,membership){
 // A reviewer must be distinct from the importer. Validation alone does not approve rows.
 app.post("/v1/tenants/:tenantId/imports/:batchId/payroll/rows/:rowNumber/decision",
  membership,requirePermission("payroll.rows.decide"),requireStepUp(),async(req,res,next)=>{
  try{
   if(!checkId(req,res,"batchId"))return;
   if(!/^[1-9][0-9]{0,6}$/.test(req.params.rowNumber))return res.status(400).json({error:"Invalid row number"});
   const {decision,reason}=req.body||{};
   if(!["accepted","rejected"].includes(decision)||!validReason(reason))return res.status(400).json({error:"Decision and reason are required"});
   const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
    const batch=await client.query(
     "SELECT id,status,source_type,created_by FROM import_batches WHERE id=$1 AND tenant_id=$2 FOR UPDATE",
     [req.params.batchId,req.membership.tenantId]);
    if(!batch.rowCount)return error(404,"Import batch not found");
    const b=batch.rows[0];
    if(b.source_type!=="payroll")return error(422,"This action requires a payroll batch");
    if(b.status!=="review")return error(409,"Payroll batch is not open for review");
    if(b.created_by===req.membership.userId)return error(403,"A different member must review imported rows");
    const row=await client.query(
     "SELECT r.id AS raw_id,d.id AS decision_id,d.decision FROM raw_import_rows r "+
     "LEFT JOIN mapping_decisions d ON d.tenant_id=r.tenant_id AND d.raw_row_id=r.id AND d.method_version='payroll-validator-0.1.0' "+
     "WHERE r.tenant_id=$1 AND r.batch_id=$2 AND r.row_number=$3",
     [req.membership.tenantId,req.params.batchId,Number(req.params.rowNumber)]);
    if(!row.rowCount)return error(404,"Source row not found");
    if(!row.rows[0].decision_id)return error(409,"Validate the source batch before reviewing rows");
    if(!["candidate","held"].includes(row.rows[0].decision))return error(409,"Source row has a final review decision");
    if(decision==="accepted"&&row.rows[0].decision!=="candidate")return error(409,"Held rows cannot be accepted; reject or correct the source");
    const updated=await client.query(
     "UPDATE mapping_decisions SET decision=$1,reviewer_id=$2,reviewed_at=now(),reason=$3 "+
     "WHERE id=$4 AND tenant_id=$5 AND decision IN ('candidate','held') RETURNING id,decision,reviewed_at",
     [decision,req.membership.userId,reason.trim(),row.rows[0].decision_id,req.membership.tenantId]);
    if(!updated.rowCount)return error(409,"Source row was already decided");
    await audit(client,req.membership,"payroll_source_row_decision","mapping_decision",updated.rows[0].id,
     reason.trim(),{batchId:req.params.batchId,rowNumber:Number(req.params.rowNumber),decision});
    return {rowNumber:Number(req.params.rowNumber),decision,reviewedAt:updated.rows[0].reviewed_at};
   });
   return respond(res,result);
  }catch(e){next(e);}
 });

 // Explicitly reconcile reviewed rows to a separate SOURCE-DECLARED amount; never infer payroll compliance.
 app.post("/v1/tenants/:tenantId/imports/:batchId/payroll/pool",
  membership,requirePermission("payroll.pools.reconcile"),requireStepUp(),async(req,res,next)=>{
  try{
   if(!checkId(req,res,"batchId"))return;
   const {declaredTotal,sourceReference,reason}=req.body||{};
   const totalCents=cents(declaredTotal);
   if(totalCents===null||totalCents<=0n||!textRef(sourceReference)||!validReason(reason))
    return res.status(400).json({error:"Positive declaredTotal, sourceReference and reason required"});
   const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
    const found=await client.query(
     "SELECT id,status,source_type,created_by,source_period_start::text AS start_date,source_period_end::text AS end_date "+
     "FROM import_batches WHERE id=$1 AND tenant_id=$2 FOR UPDATE",[req.params.batchId,req.membership.tenantId]);
    if(!found.rowCount)return error(404,"Import batch not found");
    const batch=found.rows[0];
    if(batch.source_type!=="payroll")return error(422,"Not a payroll import");
    if(batch.status!=="review")return error(409,"Payroll source batch is not open for reconciliation");
    if(batch.created_by===req.membership.userId)return error(403,"Importer cannot reconcile their own payroll batch");
    if(!batch.start_date||!batch.end_date)return error(422,"Payroll batch period is required");
    const rows=await client.query(
     "SELECT r.row_number,r.payload,d.decision FROM raw_import_rows r "+
     "LEFT JOIN mapping_decisions d ON d.tenant_id=r.tenant_id AND d.raw_row_id=r.id AND d.method_version='payroll-validator-0.1.0' "+
     "WHERE r.tenant_id=$1 AND r.batch_id=$2 ORDER BY r.row_number",
     [req.membership.tenantId,req.params.batchId]);
    if(!rows.rowCount)return error(422,"Payroll batch contains no source rows");
    if(rows.rows.some(row=>!["accepted","rejected"].includes(row.decision)))
     return error(409,"Every source row must be independently accepted or rejected first");
    const accepted=rows.rows.filter(row=>row.decision==="accepted");
    if(!accepted.length)return error(422,"No accepted payroll source rows");
    let sum=0n;
    const refs=new Set();
    for(const row of accepted){
     const checks=validatePayrollRows([row.payload],{periodStart:batch.start_date,periodEnd:batch.end_date})[0];
     if(checks.errors.length)return error(422,"Accepted source row no longer passes structural validation");
     if(row.payload.period_start!==batch.start_date||row.payload.period_end!==batch.end_date)
      return error(422,"Accepted payroll rows must match the exact batch pay period");
     const ref=row.payload.source_ref.trim();
     if(refs.has(ref))return error(422,"Duplicate accepted source reference must be resolved before reconciliation");
     refs.add(ref);
     sum+=cents(row.payload.amount);
    }
    if(sum!==totalCents)return error(422,"Declared source total does not reconcile to accepted payroll rows");
    const id=randomUUID();
    await client.query(
     "INSERT INTO payroll_pools(id,tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref) "+
     "VALUES($1,$2,$3,$4,$5,$6,'AUD',$7)",
     [id,req.membership.tenantId,req.params.batchId,batch.start_date,batch.end_date,money(sum),sourceReference.trim()]);
    await client.query("UPDATE import_batches SET status='accepted' WHERE id=$1 AND tenant_id=$2",
     [req.params.batchId,req.membership.tenantId]);
    await audit(client,req.membership,"payroll_pool_reconciled","payroll_pool",id,reason.trim(),
     {batchId:req.params.batchId,acceptedRows:accepted.length,rejectedRows:rows.rowCount-accepted.length,sourceDeclared:true});
    return {id,batchId:req.params.batchId,periodStart:batch.start_date,periodEnd:batch.end_date,
     totalAmount:money(sum),currency:"AUD",acceptedRows:accepted.length,rejectedRows:rows.rowCount-accepted.length,
     sourceDeclared:true,externallyVerified:false};
   });
   return respond(res,result,201);
  }catch(e){next(e);}
 });

 // Draft allocates a finite, explicitly reconciled pool without ever silently creating negative residuals.
 app.post("/v1/tenants/:tenantId/payroll/pools/:poolId/allocations",
  membership,requirePermission("payroll.allocations.draft"),async(req,res,next)=>{
  try{
   if(!checkId(req,res,"poolId"))return;
   const {lines,reason}=req.body||{};
   if(!validReason(reason)||!Array.isArray(lines)||!lines.length||lines.length>100)
    return res.status(400).json({error:"Reason and 1–100 allocation lines required"});
   const prepared=[],dedupe=new Set(),totals={direct:0n,approved_allocated:0n,non_site:0n,excluded:0n};
   for(const line of lines){
    if(!line||typeof line!=="object"||Array.isArray(line)||!BUCKETS.has(line.bucketType)||
       !textRef(line.sourceReference))return res.status(400).json({error:"Invalid allocation evidence"});
    const amount=cents(line.amount),site=line.siteId||null;
    if(amount===null||amount<=0n)return res.status(400).json({error:"Allocation amount must be positive AUD cents"});
    const attributable=line.bucketType==="direct"||line.bucketType==="approved_allocated";
    if(attributable?!UUID.test(site||""):site!==null)
     return res.status(400).json({error:"Site is required only for directly or approved allocated costs"});
    const key=[line.bucketType,site||"",line.sourceReference.trim()].join("\n");
    if(dedupe.has(key))return res.status(400).json({error:"Duplicate allocation evidence line"});
    dedupe.add(key);totals[line.bucketType]+=amount;
    prepared.push({bucket:line.bucketType,site,amount,ref:line.sourceReference.trim()});
   }
   const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
    const found=await client.query(
     "SELECT p.id,p.total_amount,p.currency,b.status AS batch_status FROM payroll_pools p "+
     "JOIN import_batches b ON b.id=p.batch_id AND b.tenant_id=p.tenant_id "+
     "WHERE p.id=$1 AND p.tenant_id=$2 FOR UPDATE OF b",
     [req.params.poolId,req.membership.tenantId]);
    if(!found.rowCount)return error(404,"Payroll pool not found");
    const pool=found.rows[0];
    if(pool.currency!=="AUD"||pool.batch_status!=="accepted")
     return error(409,"Payroll pool is not source-reconciled");
    const prior=await client.query("SELECT 1 FROM allocation_runs WHERE tenant_id=$1 AND payroll_pool_id=$2 AND status='confirmed'",
     [req.membership.tenantId,req.params.poolId]);
    if(prior.rowCount)return error(409,"A confirmed allocation already exists for this payroll pool");
    const siteIds=[...new Set(prepared.map(x=>x.site).filter(Boolean))];
    if(siteIds.length){
     const siteRows=await client.query(
      "SELECT id FROM sites WHERE tenant_id=$1 AND id=ANY($2::uuid[]) AND status='active'",
      [req.membership.tenantId,siteIds]);
     if(siteRows.rowCount!==siteIds.length)return error(422,"Allocation contains an invalid or foreign site");
    }
    const available=cents(pool.total_amount);
    const allocated=Object.values(totals).reduce((a,b)=>a+b,0n);
    if(allocated>available)return error(422,"Allocation exceeds the reconciled payroll pool");
    const residual=available-allocated,id=randomUUID();
    await client.query(
     "INSERT INTO allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,allocated_amount,non_site_amount,excluded_amount,residual_amount,created_by) "+
     "VALUES($1,$2,$3,'payroll-allocation-0.1.0','review',$4,$5,$6,$7,$8,$9)",
     [id,req.membership.tenantId,req.params.poolId,money(totals.direct),money(totals.approved_allocated),
      money(totals.non_site),money(totals.excluded),money(residual),req.membership.userId]);
    for(const line of prepared){
     await client.query(
      "INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref) VALUES($1,$2,$3,$4,$5,$6)",
      [req.membership.tenantId,id,line.site,line.bucket,money(line.amount),line.ref]);
    }
    if(residual>0n)await client.query(
     "INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref) "+
     "VALUES($1,$2,NULL,'unallocated',$3,'automatic-unallocated-residual')",
     [req.membership.tenantId,id,money(residual)]);
    await audit(client,req.membership,"payroll_allocation_drafted","allocation_run",id,reason.trim(),
     {poolId:req.params.poolId,sourceDeclared:true,lineCount:prepared.length,residual:money(residual)});
    return {id,poolId:req.params.poolId,status:"review",currency:"AUD",sourceDeclaredTotal:pool.total_amount,
     direct:money(totals.direct),approvedAllocated:money(totals.approved_allocated),
     nonSite:money(totals.non_site),excluded:money(totals.excluded),unallocated:money(residual),
     reviewerRequired:true,externallyVerified:false};
   });
   return respond(res,result,201);
  }catch(e){next(e);}
 });

 // Reviewers can inspect this tenant's evidence, but not the raw payroll import.
 app.get("/v1/tenants/:tenantId/payroll/pools/:poolId/allocations/:allocationId",
  membership,requirePermission("payroll.allocations.read"),async(req,res,next)=>{
  try{
   if(!checkId(req,res,"poolId")||!checkId(req,res,"allocationId"))return;
   const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
    const record=await client.query(
     "SELECT ar.id,ar.status,ar.method_version,ar.direct_amount,ar.allocated_amount,ar.non_site_amount,"+
     "ar.excluded_amount,ar.residual_amount,ar.created_by,ar.reviewer_id,ar.approved_at,p.total_amount "+
     "FROM allocation_runs ar JOIN payroll_pools p ON p.id=ar.payroll_pool_id AND p.tenant_id=ar.tenant_id "+
     "WHERE ar.id=$1 AND ar.payroll_pool_id=$2 AND ar.tenant_id=$3",
     [req.params.allocationId,req.params.poolId,req.membership.tenantId]);
    if(!record.rowCount)return null;
    const items=await client.query(
     "SELECT site_id AS \"siteId\",bucket_type AS \"bucketType\",amount "+
     "FROM allocation_lines WHERE tenant_id=$1 AND allocation_run_id=$2 "+
     "ORDER BY bucket_type,site_id,amount",
     [req.membership.tenantId,req.params.allocationId]);
    return {allocation:record.rows[0],lines:items.rows,sourceReferencesOmitted:true,externallyVerified:false};
   });
   if(!result)return res.status(404).json({error:"Payroll allocation not found"});
   res.json(result);
  }catch(e){next(e);}
 });

 // Separate approver, fresh MFA and exact SQL reconciliation before confirmed costs enter calculations.
 app.post("/v1/tenants/:tenantId/payroll/pools/:poolId/allocations/:allocationId/confirm",
  membership,requirePermission("payroll.allocations.confirm"),requireStepUp(),async(req,res,next)=>{
  try{
   if(!checkId(req,res,"poolId")||!checkId(req,res,"allocationId"))return;
   const {reason}=req.body||{};
   if(!validReason(reason))return res.status(400).json({error:"Approval reason required"});
   const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
    const found=await client.query(
     "SELECT ar.id,ar.status,ar.created_by,ar.direct_amount,ar.allocated_amount,ar.non_site_amount,"+
     "ar.excluded_amount,ar.residual_amount,p.total_amount,p.currency FROM allocation_runs ar "+
     "JOIN payroll_pools p ON p.id=ar.payroll_pool_id AND p.tenant_id=ar.tenant_id "+
     "WHERE ar.id=$1 AND ar.payroll_pool_id=$2 AND ar.tenant_id=$3 FOR UPDATE OF ar",
     [req.params.allocationId,req.params.poolId,req.membership.tenantId]);
    if(!found.rowCount)return error(404,"Payroll allocation not found");
    const row=found.rows[0];
    if(row.status!=="review")return error(409,"Allocation is no longer pending approval");
    if(!row.created_by||row.created_by===req.membership.userId)
     return error(403,"Independent allocation approver required");
    if(row.currency!=="AUD")return error(422,"Unsupported payroll currency");
    const counts=await client.query(
     "SELECT COUNT(*)::int AS line_count,COALESCE(SUM(amount),0)::numeric(14,2) AS total,"+
     "COALESCE(SUM(amount) FILTER(WHERE bucket_type='direct'),0)::numeric(14,2) AS direct,"+
     "COALESCE(SUM(amount) FILTER(WHERE bucket_type='approved_allocated'),0)::numeric(14,2) AS allocated,"+
     "COALESCE(SUM(amount) FILTER(WHERE bucket_type='non_site'),0)::numeric(14,2) AS non_site,"+
     "COALESCE(SUM(amount) FILTER(WHERE bucket_type='excluded'),0)::numeric(14,2) AS excluded,"+
     "COALESCE(SUM(amount) FILTER(WHERE bucket_type='unallocated'),0)::numeric(14,2) AS residual,"+
     "COUNT(*) FILTER(WHERE (bucket_type IN ('direct','approved_allocated')) IS DISTINCT FROM (site_id IS NOT NULL))::int AS bad_sites "+
     "FROM allocation_lines WHERE tenant_id=$1 AND allocation_run_id=$2",
     [req.membership.tenantId,row.id]);
    const check=counts.rows[0];
    if(!check.line_count||check.bad_sites||
       cents(check.total)!==cents(row.total_amount)||
       cents(check.direct)!==cents(row.direct_amount)||
       cents(check.allocated)!==cents(row.allocated_amount)||
       cents(check.non_site)!==cents(row.non_site_amount)||
       cents(check.excluded)!==cents(row.excluded_amount)||
       cents(check.residual)!==cents(row.residual_amount))
     return error(422,"Allocation lines do not reconcile exactly to the source pool");
    const updated=await client.query(
     "UPDATE allocation_runs SET status='confirmed',reviewer_id=$1,approved_at=now(),approval_reason=$2 "+
     "WHERE id=$3 AND tenant_id=$4 AND status='review' RETURNING id,status,approved_at",
     [req.membership.userId,reason.trim(),row.id,req.membership.tenantId]);
    if(!updated.rowCount)return error(409,"Allocation approval conflicted with another decision");
    await audit(client,req.membership,"payroll_allocation_confirmed","allocation_run",row.id,reason.trim(),
     {poolId:req.params.poolId,totalAmount:row.total_amount,independentApprover:true});
    return {id:row.id,poolId:req.params.poolId,status:"confirmed",approvedAt:updated.rows[0].approved_at,
     totalAmount:row.total_amount,sourceDeclared:true,externallyVerified:false};
   });
   return respond(res,result);
  }catch(e){next(e);}
 });
}
