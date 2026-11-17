// Strict canonical invoice import, separate from legacy CSV structural validation.
import {isIsoDate} from "./engine.js";
export const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MONEY=/^-?(0|[1-9]\d{0,11})\.\d{2}$/;
const NUMBER=/^[A-Z0-9][A-Z0-9._/-]{0,79}$/;
const bases=new Set(["gst_exclusive","no_gst"]);
const fail=message=>({error:message});
const validMoney=v=>typeof v==="string"&&MONEY.test(v)&&v!=="-0.00";
const cents=v=>BigInt(v.replace(".",""));
const boundedText=(v,max)=>typeof v==="string"&&v.trim().length>0&&v.length<=max&&!/[\x00-\x1f\x7f]/.test(v);
const uuid=v=>typeof v==="string"&&UUID.test(v);
export function reconcileInvoiceRows(raw,manifest,{periodStart,periodEnd}={}){
 if(!Array.isArray(raw)||raw.length<1||raw.length>200||!Array.isArray(manifest)||manifest.length<1||manifest.length>200)return fail("One to 200 source rows and declared invoices required");
 if(!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart)return fail("Valid batch service dates required");
 const declared=new Map();
 for(const h of manifest){
  if(!h||typeof h.invoiceNumber!=="string"||!NUMBER.test(h.invoiceNumber)||!validMoney(h.total)||!Number.isInteger(h.lineCount)||h.lineCount<1||h.lineCount>200||declared.has(h.invoiceNumber))return fail("Invalid or duplicate declared invoice");
  declared.set(h.invoiceNumber,h);
 }
 const groups=new Map(),seen=new Set();
 for(let i=0;i<raw.length;i++){
  const row=raw[i],p=row?.payload;
  if(!row||row.row_number!==i+1||!uuid(row.id)||!p||typeof p!=="object"||Array.isArray(p))return fail("Invalid persisted source row sequence");
  if(!boundedText(p.invoice_id,80)||!NUMBER.test(p.invoice_id)||!declared.has(p.invoice_id)||!isIsoDate(p.date)||!validMoney(p.amount)||!Number.isInteger(p.line_number)||p.line_number<1||p.line_number>200||!boundedText(p.description,500)||p.currency!=="AUD"||!bases.has(p.tax_basis)||!uuid(p.contract_id)||!uuid(p.site_id)||!isIsoDate(p.service_start)||!isIsoDate(p.service_end)||p.service_start<periodStart||p.service_end>periodEnd||p.service_end<p.service_start)return fail("Invalid or unsupported invoice source row "+(i+1));
  const k=p.invoice_id+":"+p.line_number;
  if(seen.has(k))return fail("Duplicate invoice line");
  seen.add(k);
  let g=groups.get(p.invoice_id);
  if(!g){g={number:p.invoice_id,date:p.date,taxBasis:p.tax_basis,total:declared.get(p.invoice_id).total,lines:[]};groups.set(p.invoice_id,g);}
  if(g.date!==p.date||g.taxBasis!==p.tax_basis)return fail("Inconsistent invoice header");
  g.lines.push({rawId:row.id,lineNumber:p.line_number,description:p.description.trim(),amount:p.amount,contractId:p.contract_id.toLowerCase(),siteId:p.site_id.toLowerCase(),serviceStart:p.service_start,serviceEnd:p.service_end});
 }
 if(groups.size!==declared.size)return fail("Declared invoice absent from source");
 for(const g of groups.values()){
  g.lines.sort((a,b)=>a.lineNumber-b.lineNumber);
  if(g.lines.length!==declared.get(g.number).lineCount||g.lines.some((l,i)=>l.lineNumber!==i+1)||g.lines.reduce((n,l)=>n+cents(l.amount),0n)!==cents(g.total))return fail("Invoice lines do not reconcile to declared count and total");
 }
 return {groups:[...groups.values()].sort((a,b)=>a.number.localeCompare(b.number))};
}
