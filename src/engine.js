// ProfitPilot prototype calculation and import engine.
// Deterministic demo logic only. Do not use with real payroll/customer data.
export const money = value => Math.round((Number(value) + Number.EPSILON) * 100) / 100;
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
  if(new Set(headers).size!==headers.length) throw new Error("CSV contains duplicate column headings.");
  return rows.map((cells,index)=>Object.fromEntries(headers.map((h,i)=>[h,(cells[i]??"").trim()]).concat([["__rowNumber",String(index+2)]])));
}
export function validateInvoiceRows(rows){
  return rows.map((r,i)=>{
    const amount=Number(r.amount);
    const errors=[];
    if(!r.invoice_id)errors.push("Missing invoice_id");
    if(!r.site)errors.push("Missing site");
    if(!r.date||Number.isNaN(Date.parse(r.date)))errors.push("Invalid date");
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
