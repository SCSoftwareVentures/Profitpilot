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
  return rows.map((r,i)=>{
    const amount=Number(r.amount);
    const errors=[];
    if(!r.invoice_id)errors.push("Missing invoice_id");
    if(!r.site)errors.push("Missing site");
    if(!isIsoDate(r.date))errors.push("Invalid date (expected a real YYYY-MM-DD date)");
    if(!r.amount||!Number.isFinite(amount)||amount<=0)errors.push("Amount must be greater than zero");
    return {rowNumber:r.__rowNumber||i+2,record:r,errors,status:errors.length?"held":"pending_review"};
  });
}
function payrollCents(value) {
  if (typeof value !== "string" && typeof value !== "number") return null;
  const raw = String(value).trim();
  if (!/^-?\\d+(?:\\.\\d{1,2})?$/.test(raw)) return null;
  const negative = raw.startsWith("-");
  const [whole, fraction = ""] = (negative ? raw.slice(1) : raw).split(".");
  const cents = BigInt(whole) * 100n + BigInt(fraction.padEnd(2, "0"));
  return cents > BigInt(Number.MAX_SAFE_INTEGER) ? null : (negative ? -cents : cents);
}
export function allocatePayroll({pool,direct=[],approved=[],nonSite=0,excluded=0}){
  const errors = [];
  if (!Array.isArray(direct) || !Array.isArray(approved)) return {reconciles:false,errors:["Invalid allocation list"]};
  const amounts = [pool,nonSite,excluded,...direct.map(x=>x?.amount),...approved.map(x=>x?.amount)];
  const cents = amounts.map(payrollCents);
  if (cents.some(v=>v===null || v<0n)) return {reconciles:false,errors:["Invalid, negative or sub-cent payroll amount"]};
  const [p,n,e] = cents;
  const d = cents.slice(3,3+direct.length).reduce((s,v)=>s+v,0n);
  const a = cents.slice(3+direct.length).reduce((s,v)=>s+v,0n);
  const residual = p-d-a-n-e;
  const siteCents = new Map();
  for (const [i,x] of [...direct,...approved].entries()) {
    if (typeof x?.site !== "string" || !x.site.trim()) errors.push("Missing allocation site");
    else siteCents.set(x.site,(siteCents.get(x.site)||0n)+cents[i+3]);
  }
  if (residual<0n) errors.push("Allocation exceeds eligible payroll pool");
  if ([p,d,a,n,e,residual,...siteCents.values()].some(v=>v>BigInt(Number.MAX_SAFE_INTEGER))) errors.push("Payroll total exceeds safe cent precision");
  const dollars = v => Number(v)/100;
  return {pool:dollars(p),direct:dollars(d),approvedAllocated:dollars(a),nonSite:dollars(n),excluded:dollars(e),unallocated:dollars(residual),siteTotals:Object.fromEntries([...siteCents].map(([k,v])=>[k,dollars(v)])),reconciles:errors.length===0,errors};
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
