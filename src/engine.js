// ProfitPilot prototype calculation and import engine.
// Deterministic demo logic only. Do not use with real payroll/customer data.
export const money = value => Math.round((Number(value) + Number.EPSILON) * 100) / 100;
export function isIsoDate(value){
  if(typeof value!=="string"||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value))return false;
  const date=new Date(value+"T00:00:00.000Z");
  return Number.isFinite(date.getTime())&&date.toISOString().slice(0,10)===value;
}
export function parseCsv(text) {
  const rows=[]; let row=[], cell="", quoted=false;
  for(let i=0;i<text.length;i++){
    const c=text[i], n=text[i+1];
    if(c==='"' && quoted && n==='"'){cell+='"';i++;}
    else if(c==='"'){quoted=!quoted;}
    else if(c===',' && !quoted){row.push(cell);cell="";}
    else if((c==="\n"||c==="\r")&&!quoted){if(c==="\r"&&n==="\n")i++;row.push(cell);if(row.some(v=>v.trim()!==""))rows.push(row);row=[];cell="";}
    else cell+=c;
  }
  if(quoted) throw new Error("CSV contains an unclosed quoted field.");
  row.push(cell);if(row.some(v=>v.trim()!==""))rows.push(row);
  if(!rows.length) return [];
  const headers=rows.shift().map(v=>v.trim());
  if(headers.some(h=>!h)) throw new Error("CSV contains an empty column heading.");
  if(new Set(headers).size!==headers.length) throw new Error("CSV contains duplicate column headings.");
  return rows.map((cells,index)=>{
    if(cells.length!==headers.length) throw new Error("CSV row "+(index+2)+" has "+cells.length+" cells; expected "+headers.length+".");
    return Object.fromEntries(headers.map((h,i)=>[h,cells[i].trim()]).concat([["__rowNumber",String(index+2)]]));
  });
}
export function validateInvoiceRows(rows){
  const counts=new Map();
  for(const r of rows){
    const id=typeof r.invoice_id==="string"?r.invoice_id.trim():"";
    if(id)counts.set(id,(counts.get(id)||0)+1);
  }
  return rows.map((r,i)=>{
    const amount=Number(r.amount);
    const errors=[];
    const id=typeof r.invoice_id==="string"?r.invoice_id.trim():"";
    if(!id)errors.push("Missing invoice_id");
    else if(counts.get(id)>1)errors.push("Repeated invoice reference in batch; issuer and duplicate review required");
    if(!r.site)errors.push("Missing site");
    if(!isIsoDate(r.date))errors.push("Invalid date (expected a real YYYY-MM-DD date)");
    if(!r.amount||!Number.isFinite(amount)||amount<=0)errors.push("Amount must be greater than zero");
    return {rowNumber:r.__rowNumber||i+2,record:r,errors,status:errors.length?"held":"pending_review"};
  });
}
export function allocatePayroll({pool,direct=[],approved=[],nonSite=0,excluded=0}){
  const p=money(pool),d=money(direct.reduce((s,x)=>s+Number(x.amount||0),0)),a=money(approved.reduce((s,x)=>s+Number(x.amount||0),0)),n=money(nonSite),e=money(excluded);
  const residual=money(p-d-a-n-e);
  const siteTotals={};
  for(const x of [...direct,...approved])siteTotals[x.site]=(siteTotals[x.site]||0)+Number(x.amount||0);
  const valid=[p>=0,d>=0,a>=0,n>=0,e>=0,residual>=0,Object.values(siteTotals).every(v=>v>=0)];
  return {pool:p,direct:d,approvedAllocated:a,nonSite:n,excluded:e,unallocated:residual,siteTotals:Object.fromEntries(Object.entries(siteTotals).map(([k,v])=>[k,money(v)])),reconciles:valid.every(Boolean)&&money(d+a+n+e+residual)===p,errors:valid.every(Boolean)?[]:["Negative pool, bucket or allocation exceeds eligible payroll pool"]};
}
export function matchInvoice(row,contract){
  const identity=!!row.site&&row.site===contract.site;
  const period=!!row.date&&row.date>=contract.periodStart&&row.date<=contract.periodEnd;
  const amount=Number.isFinite(Number(row.amount))&&Number(row.amount)>0;
  const evidence=[identity,period,amount].filter(Boolean).length;
  const confidence=identity&&period&&amount?"MEDIUM":identity&&amount?"LOW":"UNMATCHED";
  return {contractId:contract.id,confidence,evidence:{identity,period,amount},requiresHumanConfirmation:true};
}
export function summariseContracts(contracts){
  return contracts.map(c=>({...c,revenue:money(c.revenue),cost:money(c.cost),contribution:money(c.revenue-c.cost),margin:c.revenue?money((c.revenue-c.cost)/c.revenue*100):null}));
}
export function aggregateMetrics(contracts){
  const rows=summariseContracts(contracts);
  const revenue=money(rows.reduce((s,r)=>s+r.revenue,0)),cost=money(rows.reduce((s,r)=>s+r.cost,0));
  return {revenue,cost,contribution:money(revenue-cost),margin:revenue?money((revenue-cost)/revenue*100):null,contracts:rows};
}

export function payrollCents(value){
  if(typeof value!=="string"||!/^\d{1,12}(?:\.\d{1,2})?$/.test(value))return null;
  const [whole,fraction=""]=value.split(".");
  return Number(whole)*100+Number(fraction.padEnd(2,"0"));
}
export function centsDecimal(cents){
  if(!Number.isSafeInteger(cents)||cents<0||cents>99999999999999)throw new RangeError("Payroll amount out of range");
  return Math.floor(cents/100)+"."+String(cents%100).padStart(2,"0");
}
export function validatePayrollRows(rows,{periodStart,periodEnd}={}){
  const counts=new Map();
  for(const r of rows)if(typeof r.source_ref==="string")counts.set(r.source_ref,(counts.get(r.source_ref)||0)+1);
  return rows.map((r,i)=>{
    const errors=[],cents=payrollCents(r.amount);
    if(typeof r.source_ref!=="string"||!r.source_ref.trim()||r.source_ref!==r.source_ref.trim()||r.source_ref.length>200)errors.push("Stable source_ref required");
    else if(counts.get(r.source_ref)>1)errors.push("Duplicate source_ref in batch");
    if(cents===null||cents<=0)errors.push("Positive decimal amount string required");
    if(typeof r.currency!=="string"||!/^[A-Z]{3}$/.test(r.currency))errors.push("Explicit three-letter currency required");
    if(!isIsoDate(r.period_start)||!isIsoDate(r.period_end)||r.period_start!==periodStart||r.period_end!==periodEnd)errors.push("Payroll period must match batch");
    return {rowNumber:i+1,record:r,cents,errors,status:errors.length?"held":"pending_review"};
  });
}
export function reconcilePayroll(rows,assignments,controlTotal,currency){
  const expected=payrollCents(controlTotal);
  if(expected===null||expected<=0||typeof currency!=="string"||!/^[A-Z]{3}$/.test(currency))throw new Error("Valid control total and currency required");
  const byRow=new Map(),buckets={direct:0,approved_allocated:0,non_site:0,excluded:0,unallocated:0};
  for(const a of assignments){
    if(!a||!Number.isSafeInteger(a.rowNumber)||a.rowNumber<1||a.rowNumber>rows.length)throw new Error("Invalid allocation row");
    if(!Object.hasOwn(buckets,a.bucket)||a.bucket==="unallocated")throw new Error("Invalid allocation bucket");
    if(typeof a.reason!=="string"||a.reason.trim().length<3||a.reason.length>500)throw new Error("Allocation evidence or reason required");
    const siteBucket=a.bucket==="direct"||a.bucket==="approved_allocated";
    if(siteBucket?typeof a.siteId!=="string"||!a.siteId:a.siteId!=null)throw new Error("Site ID required only for site allocations");
    const list=byRow.get(a.rowNumber)||[],siteId=a.siteId?.toLowerCase()??null;
    if(list.some(x=>x.bucket===a.bucket&&x.siteId===siteId))throw new Error("Duplicate allocation destination");
    const cents=a.amount===undefined?null:payrollCents(a.amount);
    if(a.amount!==undefined&&(cents===null||cents<=0))throw new Error("Positive decimal split amount required");
    list.push({bucket:a.bucket,siteId,reason:a.reason.trim(),cents});
    byRow.set(a.rowNumber,list);
  }
  let total=0;
  const lines=rows.flatMap((r,i)=>{
    if(r.errors.length||r.record.currency!==currency)throw new Error("Held or currency-mismatched payroll row");
    total+=r.cents;
    if(!Number.isSafeInteger(total)||total>99999999999999)throw new Error("Payroll total exceeds supported precision");
    const list=byRow.get(i+1)||[];
    if(list.length>1&&list.some(a=>a.cents===null))throw new Error("Every split must specify its amount");
    let allocated=0;
    const parts=list.map(a=>{
      const cents=a.cents===null?r.cents:a.cents;
      allocated+=cents;
      if(allocated>r.cents)throw new Error("Allocation exceeds source row amount");
      buckets[a.bucket]+=cents;
      return {rowNumber:i+1,sourceRef:r.record.source_ref,amount:centsDecimal(cents),bucket:a.bucket,siteId:a.siteId,reason:a.reason};
    });
    const residual=r.cents-allocated;
    if(residual>0){buckets.unallocated+=residual;parts.push({rowNumber:i+1,sourceRef:r.record.source_ref,amount:centsDecimal(residual),bucket:"unallocated",siteId:null,reason:"No supported assignment"});}
    return parts;
  });
  if(total!==expected)throw new Error("Imported payroll does not reconcile to control total");
  return {total:centsDecimal(total),buckets:Object.fromEntries(Object.entries(buckets).map(([k,v])=>[k,centsDecimal(v)])),lines};
}
