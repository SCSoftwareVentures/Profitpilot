// Versioned, conservative management contribution report. No financial advice.
import {withTenant} from "./db.js";
import {requirePermission} from "./auth.js";
import {isIsoDate} from "../src/engine.js";
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VERSION="0.2.0";
const MAX=500;
const error=message=>({error:message});
function cents(n){
 if(typeof n!=="string"||! /^-?\d+\.\d{2}$/.test(n))throw new Error("Invalid database money precision");
 const neg=n[0]==="-";const v=BigInt(n.replace(/[.-]/g,""));return neg?-v:v;
}
function decimal(n){const sign=n<0n?"-":"";const v=n<0n?-n:n;return sign+(v/100n)+"."+String(v%100n).padStart(2,"0");}
const sum=(rows,field)=>rows.reduce((n,r)=>n+cents(r[field]),0n);
export function buildContribution(snapshot){
 const {baseline,invoiceEvidence,payrollEvidence,pools}=snapshot;
 if(!baseline||baseline.contractCount!==1||baseline.versionCount!==1||!baseline.versionId||baseline.currency!=="AUD")
  return error("A single attributable business contract and one approved AUD contract version covering the whole service period are required.");
 if(invoiceEvidence.length>MAX||payrollEvidence.length>MAX||pools.length>MAX)return error("Evidence limit exceeded; use a smaller aligned service period.");
 if(!invoiceEvidence.length||!payrollEvidence.length)return error("Insufficient confirmed invoice and payroll allocation evidence.");
 if(invoiceEvidence.some(r=>!r.contained||!r.reviewed||!["HIGH","MEDIUM"].includes(r.confidence)||r.currency!=="AUD"||!["gst_exclusive","no_gst"].includes(r.taxBasis)))return error("Missing, partial, unreviewed, low-confidence or incompatible invoice evidence.");
 if(new Set(invoiceEvidence.map(r=>r.taxBasis)).size!==1)return error("Mixed invoice tax basis requires explicit reconciliation.");
 if(payrollEvidence.some(r=>!r.contained||!r.reviewed||r.currency!=="AUD"||!["direct","approved_allocated"].includes(r.bucketType)))return error("Payroll evidence must be confirmed, reviewed and entirely contained in the service period.");
 const ids=new Set(payrollEvidence.map(r=>r.poolId));
 if(pools.length!==ids.size||pools.some(p=>!ids.has(p.id)))return error("Payroll pool evidence is incomplete.");
 const ordered=[...pools].sort((a,b)=>a.start.localeCompare(b.start));
 for(let i=1;i<ordered.length;i++)if(ordered[i].start<=ordered[i-1].end)return error("Overlapping payroll pools require reconciliation before reporting.");
 const revenue=sum(invoiceEvidence,"amount");
 const direct=sum(payrollEvidence.filter(r=>r.bucketType==="direct"),"amount");
 const allocated=sum(payrollEvidence.filter(r=>r.bucketType==="approved_allocated"),"amount");
 const cost=direct+allocated;
 const outputs={reportType:"partial_management_contribution",completeness:"incomplete",currency:"AUD",taxBasis:invoiceEvidence[0].taxBasis,
 revenue:decimal(revenue),directLabour:decimal(direct),approvedAllocatedLabour:decimal(allocated),
 deliveryCost:decimal(cost),contribution:decimal(revenue-cost),marginPercent:null,
 invoiceLineCount:invoiceEvidence.length,allocationLineCount:payrollEvidence.length,
 poolContext:{scope:"Entire selected payroll pools; not contract costs",sourceDeclaredTotal:decimal(sum(pools,"total")),nonSite:decimal(sum(pools,"nonSite")),excluded:decimal(sum(pools,"excluded")),unallocated:decimal(sum(pools,"unallocated")),externallyVerified:false},
 limitations:["Partial contribution after included labour only; not profit or an audited margin.","Supplier, subcontractor, other delivery costs and missing invoice evidence are not included.","Amounts are source-declared; external verification and completeness have not been established.","Site payroll is attributed only when the business has exactly one contract; no shared-contract allocation is inferred."]};
 return {outputs,inputs:{contractVersionId:baseline.versionId,contractVersion:baseline.versionNo,invoiceEvidence,payrollEvidence,pools,attributionRule:"single-contract-business",snapshotMethod:"single-statement-v1"}};
}
export function registerContributionRoutes(app,membership){
 app.post("/v1/tenants/:tenantId/calculations",membership,requirePermission("calculations.create"),async(req,res,next)=>{try{
  const {contractId,siteId,periodStart,periodEnd}=req.body||{};
  if(!UUID.test(contractId||"")||!UUID.test(siteId||"")||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart)return res.status(400).json({error:"Valid contract, site and period are required"});
  const result=await withTenant(req.membership.tenantId,req.identity.subject,async client=>{
   // One statement captures evidence under one MVCC snapshot. No raw source payloads or employee IDs.
   const q=await client.query(`
    WITH target AS (
      SELECT c.id,c.business_id FROM contracts c JOIN sites s ON s.tenant_id=c.tenant_id AND s.business_id=c.business_id
      WHERE c.tenant_id=$1 AND c.id=$2 AND s.id=$3 AND c.status='active' AND s.status='active'
    ), versions AS (
      SELECT cv.* FROM contract_versions cv JOIN target t ON t.id=cv.contract_id
      WHERE cv.tenant_id=$1 AND cv.approved_at IS NOT NULL AND cv.approved_by IS NOT NULL
       AND cv.effective_from <= $5::date AND (cv.effective_to IS NULL OR cv.effective_to >= $4::date)
    ), invoices_selected AS (
      SELECT mr.id AS "matchId",il.id AS "invoiceLineId",i.id AS "invoiceId",il.amount::text AS amount,
       i.currency AS currency,i.tax_basis AS "taxBasis",mr.confidence,
       mr.service_period_start::text AS "serviceStart",mr.service_period_end::text AS "serviceEnd",
       COALESCE(mr.service_period_start >= $4::date AND mr.service_period_end <= $5::date AND mr.service_period_end >= mr.service_period_start,false) AS contained,
       (mr.reviewer_id IS NOT NULL AND mr.reviewed_at IS NOT NULL) AS reviewed
      FROM match_reviews mr JOIN invoice_lines il ON il.id=mr.invoice_line_id AND il.tenant_id=mr.tenant_id
      JOIN invoices i ON i.id=il.invoice_id AND i.tenant_id=il.tenant_id
      WHERE mr.tenant_id=$1 AND mr.contract_id=$2 AND mr.site_id=$3 AND mr.decision='confirmed' AND i.direction='customer'
      AND (mr.service_period_start IS NULL OR mr.service_period_end IS NULL OR mr.service_period_end < mr.service_period_start
       OR (mr.service_period_start <= $5::date AND mr.service_period_end >= $4::date))
      ORDER BY mr.id LIMIT 501
    ), labour AS (
      SELECT al.id AS "allocationLineId",ar.id AS "allocationId",pp.id AS "poolId",al.bucket_type AS "bucketType",al.amount::text AS amount,
       pp.currency,pp.period_start::text AS "periodStart",pp.period_end::text AS "periodEnd",
       (pp.period_start >= $4::date AND pp.period_end <= $5::date) AS contained,
       (ar.reviewer_id IS NOT NULL AND ar.approved_at IS NOT NULL) AS reviewed
      FROM allocation_lines al JOIN allocation_runs ar ON ar.id=al.allocation_run_id AND ar.tenant_id=al.tenant_id
       JOIN payroll_pools pp ON pp.id=ar.payroll_pool_id AND pp.tenant_id=ar.tenant_id
      WHERE al.tenant_id=$1 AND al.site_id=$3 AND al.bucket_type IN ('direct','approved_allocated') AND ar.status='confirmed'
       AND pp.period_start <= $5::date AND pp.period_end >= $4::date
      ORDER BY al.id LIMIT 501
    ), selected_pools AS (
      SELECT pp.id,ar.id AS "allocationId",pp.period_start::text AS start,pp.period_end::text AS end,
       pp.total_amount::text AS total,ar.non_site_amount::text AS "nonSite",ar.excluded_amount::text AS excluded,ar.residual_amount::text AS unallocated
      FROM payroll_pools pp JOIN allocation_runs ar ON ar.payroll_pool_id=pp.id AND ar.tenant_id=pp.tenant_id AND ar.status='confirmed'
      WHERE pp.tenant_id=$1 AND pp.id IN (SELECT "poolId" FROM labour) ORDER BY pp.id LIMIT 501
    )
    SELECT (SELECT jsonb_build_object('contractCount',(SELECT count(*) FROM contracts c WHERE c.tenant_id=$1 AND c.business_id=t.business_id),
       'versionCount',(SELECT count(*) FROM versions),'versionId',v.id,'versionNo',v.version_no,'currency',v.currency)
      FROM target t LEFT JOIN LATERAL (SELECT * FROM versions WHERE effective_from <= $4::date AND (effective_to IS NULL OR effective_to >= $5::date) LIMIT 1) v ON true) AS baseline,
     COALESCE((SELECT jsonb_agg(i ORDER BY i."matchId") FROM invoices_selected i),'[]'::jsonb) AS "invoiceEvidence",
     COALESCE((SELECT jsonb_agg(l ORDER BY l."allocationLineId") FROM labour l),'[]'::jsonb) AS "payrollEvidence",
     COALESCE((SELECT jsonb_agg(p ORDER BY p.id) FROM selected_pools p),'[]'::jsonb) AS pools
   `,[req.membership.tenantId,contractId,siteId,periodStart,periodEnd]);
   const result=buildContribution(q.rows[0]);if(result.error)return result;
   const saved=await client.query("INSERT INTO calculation_runs(tenant_id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'incomplete',$9) RETURNING id,created_at",
    [req.membership.tenantId,contractId,siteId,periodStart,periodEnd,VERSION,JSON.stringify(result.inputs),JSON.stringify(result.outputs),req.membership.userId]);
   await client.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata) VALUES($1,$2,'calculation_created','calculation_run',$3,'Versioned partial management contribution evidence snapshot',$4)",
    [req.membership.tenantId,req.membership.userId,saved.rows[0].id,JSON.stringify({formulaVersion:VERSION,periodStart,periodEnd})]);
   return {id:saved.rows[0].id,createdAt:saved.rows[0].created_at,formulaVersion:VERSION,completeness:"incomplete",outputs:result.outputs};
  });
  if(result.error)return res.status(422).json({error:result.error});
  res.status(201).json(result);
 }catch(e){next(e);}});
}
