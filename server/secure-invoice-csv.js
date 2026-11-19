import {TextDecoder} from "node:util";
import {MAX_QUARANTINE_BYTES} from "./quarantine.js";
import {isIsoDate} from "../src/engine.js";

export const MAX_INVOICE_ROWS=200;
const required=["invoice_id","site","date","amount"];
const allowed=new Set([...required,"customer_id","contract_id","site_id","service_period_start","service_period_end","currency","tax_basis"]);
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const money=/^[+-]?[0-9]{1,12}(?:\.[0-9]{1,2})?$/;
export class UnsafeCsvError extends Error {
 constructor(){super("CSV rejected by secure invoice content validation");this.name="UnsafeCsvError";}
}
const reject=()=>{throw new UnsafeCsvError();};

// Exactly one physical line per source record. Reject ambiguous syntax instead
// of silently repairing it. No formulas are evaluated and no values are logged.
function cellsOf(line){
 const cells=[];let cell="",state="start";
 const push=()=>{cells.push(cell);cell="";state="start";if(cells.length>allowed.size)reject();};
 for(let i=0;i<line.length;i++){
  const c=line[i];
  if(state==="quoted"){
   if(c==='"'){
    if(line[i+1]==='"'){cell+='"';i++;}
    else state="closed";
   }else cell+=c;
  }else if(state==="closed"){
   if(c!==",")reject();
   push();
  }else if(c===",")push();
  else if(c==='"'){
   if(state!=="start")reject();
   state="quoted";
  }else{cell+=c;state="plain";}
  if(cell.length>512)reject();
 }
 if(state==="quoted")reject();
 push();return cells;
}

function safeReference(value,max,{allowUuid=false,required=false}={}){
 if(value.length>max||(required&&!value))reject();
 if(allowUuid&&uuid.test(value))return;
 // Use conservative ASCII references here; the DB privacy guard remains the
 // independent authoritative check before any future persisted ingestion.
 if(!/^[A-Za-z0-9 ._:/&'()-]*$/.test(value)||/^[=+\-@]/.test(value))reject();
 if(/(?:^|[^A-Za-z0-9])(?:tfn|tax[ _-]*file|medicare|passport|bank[ _-]*account|bsb|card[ _-]*number|credit[ _-]*card|cvv|cvc|password|access[ _-]*code|payslip)(?:$|[^A-Za-z0-9])/i.test(value))reject();
 if(/[0-9](?:[ .:/()-]*[0-9]){7,}/.test(value))reject();
}
function validateCell(name,value){
 // Refuse invisible format characters, Unicode lookalikes/compatibility forms,
 // control characters and ambiguous surrounding whitespace rather than normalize.
 if(value!==value.normalize("NFKC")||value!==value.trim()||/[\p{C}\p{Zl}\p{Zp}]/u.test(value))reject();
 if(name==="invoice_id")safeReference(value,128,{required:true});
 else if(name==="site")safeReference(value,160,{required:true});
 else if(["customer_id","contract_id","site_id"].includes(name))safeReference(value,128,{allowUuid:true});
 else if(name==="amount"){if(!money.test(value))reject();}
 else if(name==="date"||name.startsWith("service_period_")){if((name==="date"||value)&&!isIsoDate(value))reject();}
 else if(name==="currency"){if(value&&!/^[A-Z]{3}$/.test(value))reject();}
 else if(name==="tax_basis"){if(!["","gst_inclusive","gst_exclusive","no_gst","unknown"].includes(value))reject();}
 else reject();
}

// Restricted workers alone consume canonical parsed rows; the preflight wrapper
// returns only a count. This code never logs source values.
export function parseQuarantinedInvoiceCsv(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>MAX_QUARANTINE_BYTES)reject();
 let text;
 try{text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);}catch{reject();}
 // Tabs, embedded NUL, non-CRLF carriage returns and controls are not accepted.
 if(/[\u0000-\u0009\u000b\u000c\u000e-\u001f\u007f-\u009f]/u.test(text)||/\r(?!\n)/.test(text))reject();
 const lines=text.split(/\r?\n/);
 if(lines.at(-1)==="")lines.pop();
 if(lines.length<2||lines.length>MAX_INVOICE_ROWS+1||lines.some(line=>!line))reject();
 const headers=cellsOf(lines[0]);
 if(headers.some(h=>!allowed.has(h))||new Set(headers).size!==headers.length||required.some(h=>!headers.includes(h)))reject();
 const rows=[];
 for(let i=1;i<lines.length;i++){
  const values=cellsOf(lines[i]);
  if(values.length!==headers.length)reject();
  headers.forEach((h,j)=>validateCell(h,values[j]));
  const start=values[headers.indexOf("service_period_start")],end=values[headers.indexOf("service_period_end")];
  if(start&&end&&start>end)reject();
  rows.push(Object.fromEntries(headers.map((h,j)=>[h,values[j]])));
 }
 return rows;
}
export function inspectInvoiceCsv(bytes){return {rowCount:parseQuarantinedInvoiceCsv(bytes).length};}
