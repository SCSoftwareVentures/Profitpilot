export const uuidPattern=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const money=/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/;
const rowKey=/^ppr_[a-f0-9]{64}$/;
export const isDigest=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
export function uuid(value){const v=String(value??"").trim().toLowerCase();if(!uuidPattern.test(v))throw Error("A valid UUID is required.");return v;}
export function amount(value){if(typeof value!=="string"||!money.test(value))throw Error("Use an exact nonnegative two-decimal AUD amount.");return value;}
export function cents(value){return BigInt(amount(value).replace(".",""));}
export function decimal(n){if(typeof n!=="bigint"||n<0n||n>99999999999999n)throw Error("Amount exceeds supported capacity.");return String(n/100n)+"."+String(n%100n).padStart(2,"0");}
export function date(value){if(typeof value!=="string"||!/^\d{4}-\d{2}-\d{2}$/.test(value)||!Number.isFinite(Date.parse(value))||new Date(value).toISOString().slice(0,10)!==value||value.startsWith("0000"))throw Error("Use a valid calendar date.");return value;}
export function range(a,b){if(date(a)>date(b))throw Error("Period end must not precede its start.");return [a,b];}
export function parseMinimizedRows(value){
 if(typeof value!=="string"||value.length>30000)throw Error("Source exceeds candidate capacity.");
 const lines=value.split("\n");if(lines.at(-1)==="")lines.pop();
 if(lines.length<1||lines.length>200)throw Error("Use 1–200 canonical synthetic rows.");
 const seen=new Set();let total=0n;
 const rows=lines.map(line=>{
  const fields=line.split(",");if(fields.length!==3||!rowKey.test(fields[0])||fields[0]==="ppr_"+"0".repeat(64)||fields[2]!=="AUD")throw Error("Only exact pseudonymous AUD source rows are accepted.");
  const [source_row_key,v,currency]=fields;if(seen.has(source_row_key))throw Error("Duplicate source row.");seen.add(source_row_key);total+=cents(v);return {source_row_key,amount:v,currency};
 });
 return {rows,controlTotal:decimal(total),canonical:"source_row_key,amount,currency\n"+lines.join("\n")+"\n"};
}
export function mappingLine({sourceRowKey,bucket,siteId,amount:cash,evidenceRef}){
 if(typeof sourceRowKey!=="string"||!rowKey.test(sourceRowKey)||sourceRowKey==="ppr_"+"0".repeat(64)||!["approved_allocated","non_site","excluded"].includes(bucket)||typeof evidenceRef!=="string"||!/^ev_[a-f0-9]{60}$/.test(evidenceRef)||evidenceRef==="ev_"+"0".repeat(60)||cents(cash)===0n)throw Error("Invalid mapping or evidence reference.");
 return {sourceRowKey,bucket,siteId:bucket==="approved_allocated"?uuid(siteId):null,amount:cash,evidenceRef};
}
export function mappingKey(x){return [x.sourceRowKey,x.bucket,x.siteId??""].join("|");}
export function assignedSites(records,contractId){return records.contract_site.filter(x=>x.parentId===contractId).map(x=>records.site.find(s=>s.id===x.relatedId)).filter(Boolean);}
export async function checksum(text,subtle=globalThis.crypto?.subtle){if(!subtle)throw Error("Local checksum requires a secure browser context.");const b=new Uint8Array(await subtle.digest("SHA-256",new TextEncoder().encode(text)));return [...b].map(x=>x.toString(16).padStart(2,"0")).join("");}
export function tenantPath(tenant,path){if(typeof path!=="string"||!/^\/[a-z0-9/_?=&-]+$/.test(path)||path.includes("//"))throw Error("Invalid workspace route.");return "/v1/tenants/"+uuid(tenant)+path;}
