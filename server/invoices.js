import {withTenant,appendAudit} from "./db.js";
import {requirePermission,requireStepUp} from "./auth.js";
import {UUID,reconcileInvoiceRows} from "../src/canonical-invoices.js";
const METHOD="canonical-invoice-0.1.0";
const fail=(status,error)=>({status,error});
export function registerInvoiceRoutes(app,membership){
 // Recover candidate IDs following an uncertain preparation response without replaying a mutation.
 app.get("/v1/tenants/:tenantId/imports/:batchId/invoices/candidates",membership,requirePermission("matching.decide"),requireStepUp(),async(req,res,next)=>{try{
  const batchId=req.params.batchId.toLowerCase();
  if(!UUID.test(batchId))return res.status(400).json({error:"Invalid batch ID"});
  const m=req.membership;
  const result=await withTenant(m.tenantId,req.identity.subject,async c=>{
   const b=(await c.query("SELECT source_type,status FROM import_batches WHERE tenant_id=$1 AND id=$2",[m.tenantId,batchId])).rows[0];
   if(!b)return fail(404,"Invoice batch not found");
   if(!["customer_invoice","supplier_invoice"].includes(b.source_type)||b.status!=="accepted")return fail(409,"No prepared canonical invoice batch");
   const items=(await c.query(
    "SELECT r.row_number AS \"rowNumber\",i.id AS \"invoiceId\",i.invoice_number AS \"invoiceNumber\",i.direction,i.invoice_date::text AS \"invoiceDate\",i.currency,i.tax_basis AS \"taxBasis\",l.id AS \"invoiceLineId\",l.line_number AS \"lineNumber\",l.amount::text AS amount,mr.id AS \"matchId\",mr.contract_id AS \"contractId\",mr.site_id AS \"siteId\",mr.service_period_start::text AS \"serviceStart\",mr.service_period_end::text AS \"serviceEnd\",mr.confidence,mr.decision,mr.evidence #> '{sharedOverheadProposal}' AS \"sharedOverheadProposal\" "+
    "FROM raw_import_rows r JOIN mapping_decisions md ON md.tenant_id=r.tenant_id AND md.raw_row_id=r.id AND md.method_version=$3 AND md.decision='accepted' "+
    "JOIN invoice_lines l ON l.tenant_id=r.tenant_id AND l.source_row_id=r.id AND l.id=md.target_id JOIN invoices i ON i.tenant_id=l.tenant_id AND i.id=l.invoice_id "+
    "JOIN match_reviews mr ON mr.tenant_id=l.tenant_id AND mr.invoice_line_id=l.id AND mr.evidence #>> '{canonicalInvoice,batchId}'=($2::uuid)::text "+
    "WHERE r.tenant_id=$1 AND r.batch_id=$2 ORDER BY r.row_number LIMIT 201",[m.tenantId,batchId,METHOD])).rows;
   const count=(await c.query("SELECT count(*)::int AS n FROM raw_import_rows WHERE tenant_id=$1 AND batch_id=$2",[m.tenantId,batchId])).rows[0].n;
   if(!items.length||items.length>200||items.length!==count||new Set(items.map(i=>i.rowNumber)).size!==count)return fail(409,"Canonical candidate evidence is incomplete or ambiguous");
   return {batchId,items,externallyVerified:false};
  });
  if(result.error)return res.status(result.status).json({error:result.error});
  res.json(result);
 }catch(e){next(e);}});

 app.post("/v1/tenants/:tenantId/imports/:batchId/invoices/prepare",membership,requirePermission("matching.decide"),requireStepUp(),async(req,res,next)=>{try{
  const {manifest,expectedRowCount,reason,sourceReviewed}=req.body||{},batchId=req.params.batchId.toLowerCase();
  if(!UUID.test(batchId)||!Number.isInteger(expectedRowCount)||expectedRowCount<1||expectedRowCount>200||sourceReviewed!==true||typeof reason!=="string"||reason.trim().length<3||reason.length>1000)return res.status(400).json({error:"Explicit source review, declared invoice manifest, row count and reason required"});
  const m=req.membership;
  const result=await withTenant(m.tenantId,req.identity.subject,async c=>{
   const b=(await c.query("SELECT id,source_type,status,created_by,source_period_start::text AS start,source_period_end::text AS end FROM import_batches WHERE tenant_id=$1 AND id=$2 FOR UPDATE",[m.tenantId,batchId])).rows[0];
   if(!b)return fail(404,"Invoice batch not found");
   if(!["customer_invoice","supplier_invoice"].includes(b.source_type))return fail(422,"Invoice batch required");
   if(b.created_by===m.userId)return fail(403,"Independent source reviewer required");
   if(b.status!=="review")return fail(409,"Batch must be open for review");
   const raw=(await c.query("SELECT id,row_number,payload FROM raw_import_rows WHERE tenant_id=$1 AND batch_id=$2 ORDER BY row_number LIMIT 201",[m.tenantId,batchId])).rows;
   if(raw.length!==expectedRowCount)return fail(422,"Persisted row count does not match declaration");
   const parsed=reconcileInvoiceRows(raw,manifest,{periodStart:b.start,periodEnd:b.end});
   if(parsed.error)return fail(422,parsed.error);
   const direction=b.source_type==="customer_invoice"?"customer":"supplier";
   const duplicate=await c.query("SELECT 1 FROM invoices WHERE tenant_id=$1 AND direction=$2 AND upper(btrim(invoice_number))=ANY($3::text[]) LIMIT 1",[m.tenantId,direction,parsed.groups.map(g=>g.number)]);
   if(duplicate.rowCount)return fail(409,"Invoice number already exists in this direction");
   const linked=await c.query("SELECT 1 FROM invoice_lines WHERE tenant_id=$1 AND source_row_id=ANY($2::uuid[]) LIMIT 1",[m.tenantId,raw.map(r=>r.id)]);
   if(linked.rowCount)return fail(409,"Source row already linked");
   const previous=await c.query("SELECT 1 FROM mapping_decisions WHERE tenant_id=$1 AND raw_row_id=ANY($2::uuid[]) AND decision IN ('accepted','rejected') LIMIT 1",[m.tenantId,raw.map(r=>r.id)]);
   if(previous.rowCount)return fail(409,"Source row already has a final decision");
   const pairs=new Set();
   for(const g of parsed.groups)for(const l of g.lines){
    const pair=l.contractId+"|"+l.siteId;
    if(pairs.has(pair))continue;pairs.add(pair);
    const check=await c.query("SELECT 1 FROM contracts ct JOIN sites s ON s.tenant_id=ct.tenant_id AND s.business_id=ct.business_id WHERE ct.tenant_id=$1 AND ct.id=$2 AND s.id=$3 AND ct.status='active' AND s.status='active'",[m.tenantId,l.contractId,l.siteId]);
    if(!check.rowCount)return fail(422,"Source mapping must reference an active contract and site within one business");
   }
   const candidates=[];
   for(const g of parsed.groups){
    const inv=(await c.query("INSERT INTO invoices(tenant_id,direction,invoice_number,invoice_date,total_amount,currency,tax_basis,source_ref) VALUES($1,$2,$3,$4,$5,'AUD',$6,$7) RETURNING id",[m.tenantId,direction,g.number,g.date,g.total,g.taxBasis,"canonical-batch:"+batchId])).rows[0].id;
    for(const l of g.lines){
     const line=(await c.query("INSERT INTO invoice_lines(tenant_id,invoice_id,line_number,description,amount,source_row_id) VALUES($1,$2,$3,$4,$5,$6) RETURNING id",[m.tenantId,inv,l.lineNumber,l.description,l.amount,l.rawId])).rows[0].id;
     const ev={canonicalInvoice:{method:METHOD,batchId,sourceRowId:l.rawId,preparedBy:m.userId,importedBy:b.created_by,externallyVerified:false}};
     const match=(await c.query("INSERT INTO match_reviews(tenant_id,invoice_line_id,contract_id,site_id,service_period_start,service_period_end,confidence,decision,evidence) VALUES($1,$2,$3,$4,$5,$6,'MEDIUM','candidate',$7) RETURNING id",[m.tenantId,line,l.contractId,l.siteId,l.serviceStart,l.serviceEnd,JSON.stringify(ev)])).rows[0].id;
     await c.query("INSERT INTO mapping_decisions(tenant_id,raw_row_id,target_type,target_id,decision,confidence,method_version,reviewer_id,reviewed_at,reason) VALUES($1,$2,'invoice_row',$3,'accepted','MEDIUM',$4,$5,now(),$6)",[m.tenantId,l.rawId,line,METHOD,m.userId,"Source reconciliation only; match remains a candidate"]);
     candidates.push({matchId:match,invoiceLineId:line,direction});
    }
   }
   await c.query("UPDATE import_batches SET status='accepted' WHERE tenant_id=$1 AND id=$2",[m.tenantId,batchId]);
   await appendAudit(c,m,"invoice_batch_prepared","import_batch",batchId,reason.trim(),{method:METHOD,invoiceCount:parsed.groups.length,rowCount:raw.length,manifest:parsed.groups.map(g=>({invoiceNumber:g.number,total:g.total,lineCount:g.lines.length})),externallyVerified:false});
   return {batchId,invoiceCount:parsed.groups.length,rowCount:raw.length,candidates,automaticallyConfirmed:0,externallyVerified:false};
  });
  if(result.error)return res.status(result.status).json({error:result.error});
  res.status(201).json(result);
 }catch(e){next(e);}});
}
