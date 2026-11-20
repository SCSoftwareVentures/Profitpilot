// Synthetic prototype only. Never authorises financial inclusion.
export function classifyInvoiceIdentity(rows){
 if(!Array.isArray(rows))throw new TypeError("Rows must be an array");
 const seen=new Map(), aliases=new Map();
 return rows.map(row=>{
  const {direction,issuerKey,invoiceReference}=row;
  const hold=reason=>({status:"held",reason});
  if(!["customer","supplier"].includes(direction))return hold("Invalid direction");
  if(typeof issuerKey!=="string"||!issuerKey.trim()||typeof invoiceReference!=="string"||!invoiceReference.trim())return hold("Missing issuer or reference");
  const issuer=issuerKey.trim(), ref=invoiceReference.trim();
  const key=JSON.stringify([direction,issuer,ref]);
  const alias=JSON.stringify([direction,issuer,ref.toLowerCase().replace(/^0+(?=\d+$)/,"")]);
  if(seen.has(key))return hold("Repeated issuer/reference; review source lineage");
  if(aliases.has(alias))return hold("Potential reference alias; review source-owner rules");
  seen.set(key,true);aliases.set(alias,true);
  return {status:"candidate",reason:"Distinct observed reference; confirmation still required"};
 });
}
