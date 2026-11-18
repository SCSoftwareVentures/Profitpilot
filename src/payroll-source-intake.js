// Restricted offline mapping of already-minimized payroll export. No raw vendor
// extracts or employee identifiers, no storage, network or approval.
import {createHash} from "node:crypto";
import {isIsoDate} from "./engine.js";
const F="minimized-payroll-v1",HEADER="source_row_key,amount,currency\n";
const MAX=200,MAX_BYTES=65536;
const digest=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(x);
const amount=x=>typeof x==="string"&&/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(x);
const token=x=>typeof x==="string"&&/^ppr_[a-f0-9]{64}$/.test(x)&&!/^ppr_0+$/.test(x);
const sha=x=>createHash("sha256").update(x).digest("hex");
const exact=(x,k)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===k.length&&k.every(y=>Object.hasOwn(x,y));
const fields=["format","sourceNamespace","periodStart","periodEnd","currency","controlTotal","rowCount","fileSha256","authorityDigest","policyDigest","controlDigest"];
const held=code=>({status:"held",code,requiresHumanConfirmation:true,source:null});
export function inspectMinimizedPayroll(bytes,manifest){
 if(!exact(manifest,fields)||manifest.format!==F||!uuid(manifest.sourceNamespace)||manifest.currency!=="AUD"||
 !isIsoDate(manifest.periodStart)||!isIsoDate(manifest.periodEnd)||manifest.periodEnd<manifest.periodStart||
 (Date.parse(manifest.periodEnd)-Date.parse(manifest.periodStart))/86400000>366||
 !amount(manifest.controlTotal)||!Number.isSafeInteger(manifest.rowCount)||manifest.rowCount<1||manifest.rowCount>MAX||
 ![manifest.fileSha256,manifest.authorityDigest,manifest.policyDigest,manifest.controlDigest].every(digest))return held("INVALID_MANIFEST");
 if(!Buffer.isBuffer(bytes)||bytes.length<HEADER.length+1||bytes.length>MAX_BYTES||bytes.some(x=>x!==10&&(x<32||x>126)))return held("INVALID_FILE");
 if(sha(bytes)!==manifest.fileSha256)return held("CHECKSUM_MISMATCH");
 const source=bytes.toString("ascii");
 if(!source.startsWith(HEADER)||!source.endsWith("\n"))return held("INVALID_HEADER_OR_ENCODING");
 const lines=source.slice(HEADER.length,-1).split("\n");
 if(lines.length!==manifest.rowCount)return held("ROW_COUNT_MISMATCH");
 const rows=[],seen=new Set();let total=0n;
 for(const line of lines){
  const cells=line.split(",");
  if(cells.length!==3||!token(cells[0])||!amount(cells[1])||cells[2]!=="AUD")return held("INVALID_ROW");
  if(seen.has(cells[0]))return held("DUPLICATE_ROW");
  seen.add(cells[0]);total+=BigInt(cells[1].replace(".",""));
  rows.push({source_row_key:cells[0],amount:cells[1],currency:"AUD"});
 }
 if(total!==BigInt(manifest.controlTotal.replace(".","")))return held("CONTROL_TOTAL_MISMATCH");
 return {status:"pending_independent_review",requiresHumanConfirmation:true,source:{manifest:Object.fromEntries(fields.map(k=>[k,manifest[k]])),rows}};
}
