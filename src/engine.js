import {createHash} from "node:crypto";
// ProfitPilot prototype calculation and import engine.
// Deterministic demo logic only. Do not use with real payroll/customer data.
function decimalCents(value){
  const text=typeof value==="number"?(Number.isFinite(value)?String(value):""):typeof value==="string"?value.trim():"";
  if(text.length>128)return null;
  const match=text.match(/^([+-]?)(\d+)(?:\.(\d*))?(?:e([+-]?\d+))?$/i);
  if(!match)return null;
  const exponent=Number(match[4]||0);
  if(!Number.isInteger(exponent)||Math.abs(exponent)>100)return null;
  const fraction=match[3]||"";
  const digits=BigInt((match[2]+fraction).replace(/^0+(?=\d)/,""));
  const scale=fraction.length-exponent;
  if(Math.abs(scale)>100)return null;
  let cents;
  if(scale<=2)cents=digits*10n**BigInt(2-scale);
  else{
    const divisor=10n**BigInt(scale-2);
    const quotient=digits/divisor;
    const remainder=digits%divisor;
    cents=quotient+(remainder*2n>=divisor?1n:0n);
  }
  return match[1]==="-"?-cents:cents;
}
const fromCents=cents=>Number(cents)/100;
function sumCents(values){
  let total=0n;
  for(const value of values){const cents=decimalCents(value);if(cents===null)return null;total+=cents;}
  return total;
}
function ratioCents(numerator,denominator){
  if(denominator===0n)return null;
  const negative=(numerator<0n)!==(denominator<0n);
  const n=numerator<0n?-numerator:numerator;
  const d=denominator<0n?-denominator:denominator;
  const quotient=n/d,remainder=n%d;
  const rounded=quotient+(remainder*2n>=d?1n:0n);
  return negative?-rounded:rounded;
}
export const money=value=>{const cents=decimalCents(value);return cents===null?NaN:fromCents(cents);};
export function isIsoDate(value){
  if(typeof value!=="string"||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value))return false;
  const date=new Date(value+"T00:00:00.000Z");
  return Number.isFinite(date.getTime())&&date.toISOString().slice(0,10)===value;
}
export function parseCsv(text) {
  if(typeof text!=="string")throw new TypeError("CSV input must be text.");
  if(text.charCodeAt(0)===0xFEFF)text=text.slice(1);
  const rows=[]; let row=[],cell="",quoted=false,closedQuote=false;
  const pushRecord=()=>{
    row.push(cell);
    if(row.some(v=>v.trim()!==""))rows.push(row);
    row=[];cell="";closedQuote=false;
  };
  for(let i=0;i<text.length;i++){
    const c=text[i], n=text[i+1];
    if(quoted){
      if(c==='"'&&n==='"'){cell+='"';i++;}
      else if(c==='"'){quoted=false;closedQuote=true;}
      else cell+=c;
      continue;
    }
    if(closedQuote){
      if(c===","){row.push(cell);cell="";closedQuote=false;}
      else if(c===" "||c==="\t"){cell+=c;}
      else if(c==="\n"||c==="\r"){
        if(c==="\r"&&n==="\n")i++;
        pushRecord();
      }else throw new Error("CSV contains unexpected characters after a closing quote.");
      continue;
    }
    if(c==='"'){
      if(cell.length!==0)throw new Error("CSV contains a quote inside an unquoted field.");
      quoted=true;
    }else if(c===","){row.push(cell);cell="";}
    else if(c==="\n"||c==="\r"){
      if(c==="\r"&&n==="\n")i++;
      pushRecord();
    }else cell+=c;
  }
  if(quoted)throw new Error("CSV contains an unclosed quoted field.");
  row.push(cell);if(row.some(v=>v.trim()!==""))rows.push(row);
  if(!rows.length)return [];
  const headers=rows.shift().map(v=>v.trim());
  if(headers.some(h=>!h))throw new Error("CSV contains an empty column heading.");
  const normalised=headers.map(h=>h.toLocaleLowerCase("en"));
  if(new Set(normalised).size!==headers.length)throw new Error("CSV contains duplicate column headings.");
  return rows.map((cells,index)=>{
    if(cells.length!==headers.length)throw new Error("CSV row "+(index+2)+" has "+cells.length+" cells; expected "+headers.length+".");
    return Object.fromEntries(headers.map((h,i)=>[h,cells[i].trim()]).concat([["__rowNumber",String(index+2)]]));
  });
}
export function validateInvoiceRows(rows){
  return rows.map((r,i)=>{
    const amountText=String(r.amount??"").trim();
    const amount=Number(amountText);
    const errors=[];
    if(typeof r.invoice_id!=="string"||!r.invoice_id.trim())errors.push("Missing invoice_id");
    if(typeof r.site!=="string"||!r.site.trim())errors.push("Missing site");
    if(!isIsoDate(r.date))errors.push("Invalid date (expected a real YYYY-MM-DD date)");
    if(!/^\d+(?:\.\d{1,2})?$/.test(amountText)||!Number.isFinite(amount)||amount<=0)errors.push("Amount must be a positive decimal with at most two fractional digits");
    return {rowNumber:r.__rowNumber||i+2,record:r,errors,status:errors.length?"held":"pending_review"};
  });
}
export function allocatePayroll({pool,direct=[],approved=[],nonSite=0,excluded=0}){
  const p=decimalCents(pool),d=sumCents(direct.map(x=>x.amount??0)),a=sumCents(approved.map(x=>x.amount??0)),n=decimalCents(nonSite),e=decimalCents(excluded);
  const validInputs=[p,d,a,n,e].every(x=>x!==null);
  const residual=validInputs?p-d-a-n-e:null;
  const siteCents=Object.create(null);
  let sitesValid=true;
  for(const x of [...direct,...approved]){
    const amount=decimalCents(x.amount??0);
    if(amount===null){sitesValid=false;continue;}
    const key=String(x.site??"");
    siteCents[key]=(siteCents[key]||0n)+amount;
  }
  const valid=validInputs&&p>=0n&&d>=0n&&a>=0n&&n>=0n&&e>=0n&&residual>=0n&&sitesValid&&Object.values(siteCents).every(v=>v>=0n);
  const safe=v=>v===null?NaN:fromCents(v);
  return {pool:safe(p),direct:safe(d),approvedAllocated:safe(a),nonSite:safe(n),excluded:safe(e),unallocated:safe(residual),siteTotals:Object.fromEntries(Object.entries(siteCents).map(([k,v])=>[k,fromCents(v)])),reconciles:valid&&d+a+n+e+residual===p,errors:valid?[]:["Invalid monetary input, negative bucket or allocation exceeds eligible payroll pool"]};
}
export function matchInvoice(row,contract){
  const identity=typeof row.site==="string"&&row.site.trim()!==""&&row.site===contract.site;
  const period=isIsoDate(row.date)&&isIsoDate(contract.periodStart)&&isIsoDate(contract.periodEnd)&&row.date>=contract.periodStart&&row.date<=contract.periodEnd;
  const amountCents=decimalCents(row.amount);
  const amount=amountCents!==null&&amountCents>0n;
  const evidence=[identity,period,amount].filter(Boolean).length;
  const confidence=identity&&period&&amount?"MEDIUM":identity&&amount?"LOW":"UNMATCHED";
  return {contractId:contract.id,confidence,evidence:{identity,period,amount},requiresHumanConfirmation:true};
}
export function summariseContracts(contracts){
  return contracts.map(c=>{
    const revenue=decimalCents(c.revenue),cost=decimalCents(c.cost);
    if(revenue===null||cost===null)return {...c,revenue:NaN,cost:NaN,contribution:NaN,margin:null};
    const contribution=revenue-cost;
    const margin=revenue?ratioCents(contribution*10000n,revenue):null;
    return {...c,revenue:fromCents(revenue),cost:fromCents(cost),contribution:fromCents(contribution),margin:margin===null?null:fromCents(margin)};
  });
}
export function aggregateMetrics(contracts){
  const rows=summariseContracts(contracts);
  const revenue=sumCents(rows.map(r=>r.revenue)),cost=sumCents(rows.map(r=>r.cost));
  if(revenue===null||cost===null)return {revenue:NaN,cost:NaN,contribution:NaN,margin:null,contracts:rows};
  const contribution=revenue-cost;
  const margin=revenue?ratioCents(contribution*10000n,revenue):null;
  return {revenue:fromCents(revenue),cost:fromCents(cost),contribution:fromCents(contribution),margin:margin===null?null:fromCents(margin),contracts:rows};
}


/**
 * Normalize a deliberately minimal payroll source-row contract.
 * Only opaque source keys, decimal amounts and ISO currency codes survive.
 * Employee names, bank details, tax identifiers and arbitrary source columns
 * are never copied into the normalized result.
 */
export function normalizePayrollRows(rows){
  if(!Array.isArray(rows))throw new TypeError("Payroll rows must be an array.");
  if(rows.length<1||rows.length>10000)throw new RangeError("Payroll batch must contain 1–10000 rows.");
  const seen=new Set();
  return rows.map((row,index)=>{
    const errors=[];
    if(!row||typeof row!=="object"||Array.isArray(row))return {rowNumber:index+1,status:"held",record:null,errors:["Row must be an object"]};
    const key=typeof row.source_row_key==="string"?row.source_row_key.trim():"";
    const amountText=typeof row.amount==="string"?row.amount.trim():typeof row.amount==="number"&&Number.isFinite(row.amount)?String(row.amount):"";
    const currency=typeof row.currency==="string"?row.currency.trim().toUpperCase():"";
    if(!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(key))errors.push("source_row_key must be an opaque stable key (1–128 safe characters)");
    if(!/^(?:0|[1-9]\d*)(?:\.\d{1,2})?$/.test(amountText))errors.push("amount must be a non-negative decimal with at most two fractional digits");
    if(!/^[A-Z]{3}$/.test(currency))errors.push("currency must be a three-letter ISO-style code");
    if(key&&seen.has(key))errors.push("Duplicate source_row_key within this batch");
    if(key)seen.add(key);
    if(errors.length)return {rowNumber:index+1,status:"held",record:null,errors};
    const [whole,fraction=""]=amountText.split(".");
    const canonicalAmount=String(BigInt(whole))+"."+fraction.padEnd(2,"0");
    const canonical={sourceRowKey:key,amount:canonicalAmount,currency};
    const rowSha256=createHash("sha256").update([key,canonicalAmount,currency].join("\\n"),"utf8").digest("hex");
    return {rowNumber:index+1,status:"pending_review",record:canonical,rowSha256,errors:[]};
  });
}
