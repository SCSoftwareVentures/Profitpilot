// Source-declared reconciliation; never infer completeness of external accounts.
import {reconcileInvoiceRows} from "./canonical-invoices.js";
import {validatePayrollRows} from "./engine.js";
const money=value=>typeof value==="string"&&/^-?(0|[1-9]\d{0,11})(?:\.\d{1,2})?$/.test(value);
function cents(v){
 if(!money(v))throw new Error("Invalid source money");
 const neg=v.startsWith("-"),[whole,fraction=""]=v.replace(/^-/,"").split(".");
 const n=BigInt(whole)*100n+BigInt(fraction.padEnd(2,"0"));
 return neg?-n:n;
}
function decimal(v){const n=v<0n?-v:v;return (v<0n?"-":"")+(n/100n)+"."+String(n%100n).padStart(2,"0");}
function sameAmount(a,b){return money(a)&&money(b)&&cents(a)===cents(b);}
const SUM=(rows,key)=>rows.reduce((n,r)=>n+cents(r[key]),0n);
const supported=["customer_invoice","supplier_invoice","payroll"];
export function reconcileStoredSource({batch,rows,manifestEvents=[],invoiceRecords=[],payrollPools=[],allocations=[]}){
 const base={batchId:batch.id,sourceType:batch.source_type,batchStatus:batch.status,sourceStatus:"pending",approvalStatus:"pending",rowCount:rows.length,completeSourceCoverage:false,externallyVerified:false};
 const fail=(reason,extra={})=>({...base,...extra,sourceStatus:"unreconciled",reason});
 if(!supported.includes(batch.source_type))return fail("unsupported_source_type");
 if(rows.length>200)return fail("row_limit_exceeded");
 if(batch.status!=="accepted")return {...base,reason:"batch_not_sealed"};
 if(!rows.length)return fail("missing_source_rows");
 if(batch.source_type==="payroll"){
  if(rows.some(r=>!["accepted","rejected"].includes(r.decision)))return fail("unresolved_payroll_rows");
  const accepted=rows.filter(r=>r.decision==="accepted"),rejected=rows.length-accepted.length;
  const details={acceptedRowCount:accepted.length,rejectedRowCount:rejected};
  if(!accepted.length||payrollPools.length!==1)return fail("missing_or_ambiguous_payroll_pool",details);
  const pool=payrollPools[0],refs=new Set();
  for(const row of accepted){
   const q=row.payload;
   if(validatePayrollRows([q],{periodStart:batch.start,periodEnd:batch.end})[0].errors.length||q.period_start!==batch.start||q.period_end!==batch.end||!money(q.amount)||refs.has(q.source_ref.trim()))return fail("invalid_or_duplicate_accepted_payroll_row",details);
   refs.add(q.source_ref.trim());
  }
  const total=accepted.reduce((n,r)=>n+cents(r.payload.amount),0n);
  if(pool.currency!=="AUD"||pool.start!==batch.start||pool.end!==batch.end||!sameAmount(pool.total,decimal(total)))return fail("payroll_pool_total_or_period_mismatch",details);
  const matching=allocations.filter(a=>a.poolId===pool.id&&a.status==="confirmed");
  const result={...base,...details,sourceStatus:"reconciled_declared_source",acceptedTotal:decimal(total),poolTotal:pool.total,approvalStatus:"allocation_pending",rejectedRowsRequireReview:rejected>0};
  if(matching.length===0)return result;
  if(matching.length!==1)return {...result,approvalStatus:"allocation_inconsistent"};
  const a=matching[0],keys=["direct","allocated","nonSite","excluded","residual"];
  if(keys.some(k=>!money(a[k])||cents(a[k])<0n)||keys.reduce((v,k)=>v+cents(a[k]),0n)!==total||!a.reviewed||!sameAmount(a.lineTotal,decimal(total-cents(a.residual))))return {...result,approvalStatus:"allocation_inconsistent"};
  return {...result,approvalStatus:"allocation_reconciled",allocation:{direct:a.direct,allocated:a.allocated,nonSite:a.nonSite,excluded:a.excluded,residual:a.residual}};
 }
 if(manifestEvents.length!==1||!Array.isArray(manifestEvents[0]?.manifest)||manifestEvents[0]?.rowCount!==rows.length)return {...base,sourceStatus:"declaration_unavailable",reason:"missing_unique_original_manifest"};
 const parsed=reconcileInvoiceRows(rows,manifestEvents[0].manifest,{periodStart:batch.start,periodEnd:batch.end});
 if(parsed.error)return fail("source_manifest_mismatch");
 const byRaw=new Map(invoiceRecords.map(r=>[r.rawId,r]));
 if(byRaw.size!==invoiceRecords.length||invoiceRecords.length!==rows.length)return fail("canonical_row_count_mismatch");
 const direction=batch.source_type==="customer_invoice"?"customer":"supplier";
 const totals=new Map(),seen=new Set();let confirmed=0,unresolved=0;
 for(const group of parsed.groups){
  let headerId=null;
  for(const line of group.lines){
   const c=byRaw.get(line.rawId);
   if(!c||seen.has(c.lineId)||!c.lineId||!c.invoiceId||c.direction!==direction||c.invoiceNumber!==group.number||c.invoiceDate!==group.date||c.currency!=="AUD"||c.taxBasis!==group.taxBasis||!sameAmount(c.invoiceTotal,group.total)||c.headerLineCount!==group.lines.length||c.lineNumber!==line.lineNumber||!sameAmount(c.amount,line.amount)||c.description!==line.description||c.mappingDecision!=="accepted"||c.mappingTarget!==c.lineId||c.matchCount!==1||c.contractId!==line.contractId||c.siteId!==line.siteId||c.serviceStart!==line.serviceStart||c.serviceEnd!==line.serviceEnd)return fail("canonical_invoice_or_mapping_mismatch");
   if(headerId!==null&&headerId!==c.invoiceId)return fail("split_invoice_header");
   headerId=c.invoiceId;seen.add(c.lineId);
   if(c.decision==="confirmed"&&c.confirmedCount===1&&c.reviewed)confirmed++;else unresolved++;
  }
  totals.set(group.taxBasis,(totals.get(group.taxBasis)||0n)+cents(group.total));
 }
 return {...base,sourceStatus:"reconciled_declared_source",approvalStatus:unresolved?"incomplete_match_approval":"all_rows_confirmed",invoiceCount:parsed.groups.length,confirmedRowCount:confirmed,unresolvedRowCount:unresolved,totalsByTaxBasis:[...totals].sort(([a],[b])=>a.localeCompare(b)).map(([taxBasis,total])=>({taxBasis,amount:decimal(total)}))};
}
