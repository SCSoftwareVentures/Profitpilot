// Synthetic prototype only. Never authorises financial inclusion.
// Two-pass conflict grouping: no first-row preference; aliases are review signals, not canonical identities.
export function classifyInvoiceIdentity(rows){
 if(!Array.isArray(rows))throw new TypeError("Rows must be an array");
 const exactCounts=new Map(), aliasCounts=new Map();
 const increment=(map,key)=>map.set(key,(map.get(key)||0)+1);
 const hold=reason=>({status:"held",reason});
 const prepared=Array.from(rows,row=>{
  if(!row||typeof row!=="object"||Array.isArray(row))return {result:hold("Invalid row")};
  const {direction,issuerKey,invoiceReference}=row;
  if(!["customer","supplier"].includes(direction))return {result:hold("Invalid direction")};
  if(typeof issuerKey!=="string"||!issuerKey.trim()||typeof invoiceReference!=="string"||!invoiceReference.trim())return {result:hold("Missing issuer or reference")};
  const issuer=issuerKey.trim(),ref=invoiceReference.trim();
  const key=JSON.stringify([direction,issuer,ref]);
  const alias=JSON.stringify([direction,issuer,ref.toLowerCase().replace(/^0+(?=\d+$)/,"")]);
  increment(exactCounts,key);increment(aliasCounts,alias);
  return {key,alias};
 });
 return prepared.map(({result,key,alias})=>{
  if(result)return result;
  if(exactCounts.get(key)>1)return hold("Repeated issuer/reference; review source lineage");
  if(aliasCounts.get(alias)>1)return hold("Potential reference alias; review source-owner rules");
  return {status:"candidate",reason:"Distinct observed reference; confirmation still required"};
 });
}
