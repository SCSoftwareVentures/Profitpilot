import {withTenant} from "./db.js";
import {requirePermission,requireStepUp} from "./auth.js";
import {UUID} from "../src/canonical-invoices.js";
import {reconcileStoredSource} from "../src/source-reconciliation.js";
export function registerSourceReconciliationRoutes(app,membership){
 app.get("/v1/tenants/:tenantId/imports/:batchId/reconciliation",membership,requirePermission("matching.decide"),requirePermission("payroll.allocations.read"),requireStepUp(),async(req,res,next)=>{try{
  const batchId=req.params.batchId;
  if(!UUID.test(batchId))return res.status(400).json({error:"Invalid batch ID"});
  const result=await withTenant(req.membership.tenantId,req.identity.subject,async c=>{
   // One MVCC statement, no source payload or personally identifying references in the response.
   const q=await c.query(`
    WITH b AS ( SELECT id,tenant_id,source_type,status,source_period_start::text AS start,source_period_end::text AS end FROM import_batches WHERE tenant_id=$1 AND id=$2 ),
    raw AS (
      SELECT r.id,r.row_number,r.payload,md.decision
      FROM raw_import_rows r JOIN b ON b.id=r.batch_id AND b.tenant_id=r.tenant_id
      LEFT JOIN mapping_decisions md ON md.tenant_id=r.tenant_id AND md.raw_row_id=r.id AND md.method_version='payroll-validator-0.1.0'
      ORDER BY r.row_number LIMIT 201
    ), canon AS (
      SELECT r.id AS "rawId",l.id AS "lineId",i.id AS "invoiceId",i.direction,i.invoice_number AS "invoiceNumber",i.invoice_date::text AS "invoiceDate",
       i.currency,i.tax_basis AS "taxBasis",i.total_amount::text AS "invoiceTotal",l.line_number AS "lineNumber",l.description,l.amount::text,
       md.decision AS "mappingDecision",md.target_id AS "mappingTarget",
       (SELECT count(*)::int FROM invoice_lines lx WHERE lx.tenant_id=$1 AND lx.invoice_id=i.id) AS "headerLineCount",
       (SELECT count(*)::int FROM match_reviews mx WHERE mx.tenant_id=$1 AND mx.invoice_line_id=l.id AND mx.evidence #>> '{canonicalInvoice,batchId}'=($2::uuid)::text) AS "matchCount",
       (SELECT count(*)::int FROM match_reviews mx WHERE mx.tenant_id=$1 AND mx.invoice_line_id=l.id AND mx.decision='confirmed') AS "confirmedCount",
       mr.contract_id AS "contractId",mr.site_id AS "siteId",mr.service_period_start::text AS "serviceStart",mr.service_period_end::text AS "serviceEnd",mr.decision,
       (mr.reviewer_id IS NOT NULL AND mr.reviewed_at IS NOT NULL) AS reviewed
      FROM raw r JOIN invoice_lines l ON l.tenant_id=$1 AND l.source_row_id=r.id
       JOIN invoices i ON i.tenant_id=l.tenant_id AND i.id=l.invoice_id
       LEFT JOIN mapping_decisions md ON md.tenant_id=l.tenant_id AND md.raw_row_id=r.id AND md.method_version='canonical-invoice-0.1.0'
       LEFT JOIN match_reviews mr ON mr.tenant_id=l.tenant_id AND mr.invoice_line_id=l.id AND mr.evidence #>> '{canonicalInvoice,batchId}'=($2::uuid)::text
      ORDER BY r.row_number LIMIT 201
    ), pools AS (
      SELECT p.id,p.total_amount::text AS total,p.currency,p.period_start::text AS start,p.period_end::text AS end
      FROM payroll_pools p JOIN b ON b.tenant_id=p.tenant_id AND b.id=p.batch_id ORDER BY p.id LIMIT 2
    ), allocations AS (
      SELECT a.payroll_pool_id AS "poolId",a.status,a.direct_amount::text AS direct,a.allocated_amount::text AS allocated,a.non_site_amount::text AS "nonSite",a.excluded_amount::text AS excluded,a.residual_amount::text AS residual,
       (a.reviewer_id IS NOT NULL AND a.approved_at IS NOT NULL AND a.created_by IS NOT NULL AND a.created_by<>a.reviewer_id) AS reviewed,
       to_jsonb(checks) AS "lineChecks"
      FROM allocation_runs a JOIN pools p ON p.id=a.payroll_pool_id
       CROSS JOIN LATERAL (
        SELECT count(*)::int AS "lineCount",COALESCE(sum(l.amount),0)::text AS total,
         COALESCE(sum(l.amount) FILTER(WHERE l.bucket_type='direct'),0)::text AS direct,
         COALESCE(sum(l.amount) FILTER(WHERE l.bucket_type='approved_allocated'),0)::text AS allocated,
         COALESCE(sum(l.amount) FILTER(WHERE l.bucket_type='non_site'),0)::text AS "nonSite",
         COALESCE(sum(l.amount) FILTER(WHERE l.bucket_type='excluded'),0)::text AS excluded,
         COALESCE(sum(l.amount) FILTER(WHERE l.bucket_type='unallocated'),0)::text AS residual,
         count(*) FILTER(WHERE (l.bucket_type IN ('direct','approved_allocated')) IS DISTINCT FROM (l.site_id IS NOT NULL))::int AS "badSites"
        FROM allocation_lines l WHERE l.tenant_id=$1 AND l.allocation_run_id=a.id
       ) checks WHERE a.tenant_id=$1 AND a.status='confirmed' LIMIT 2
    ), manifests AS (
      SELECT metadata FROM audit_events WHERE tenant_id=$1 AND object_id=$2 AND action='invoice_batch_prepared' AND object_type='import_batch' LIMIT 2
    )
    SELECT (SELECT to_jsonb(b)-'tenant_id' FROM b) AS batch,
     COALESCE((SELECT jsonb_agg(r ORDER BY r.row_number) FROM raw r),'[]'::jsonb) AS rows,
     COALESCE((SELECT jsonb_agg(x) FROM canon x),'[]'::jsonb) AS "invoiceRecords",
     COALESCE((SELECT jsonb_agg(x.metadata) FROM manifests x),'[]'::jsonb) AS "manifestEvents",
     COALESCE((SELECT jsonb_agg(x) FROM pools x),'[]'::jsonb) AS "payrollPools",
     COALESCE((SELECT jsonb_agg(x) FROM allocations x),'[]'::jsonb) AS allocations
   `,[req.membership.tenantId,batchId]);
   const snapshot=q.rows[0];
   if(!snapshot?.batch)return null;
   return reconcileStoredSource(snapshot);
  });
  if(!result)return res.status(404).json({error:"Import batch not found"});
  res.json(result);
 }catch(e){next(e);}});
}
