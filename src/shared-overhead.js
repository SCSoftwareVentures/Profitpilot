// Exact signed-cent shared overhead allocations. No inferred weights or floating-point money.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MONEY=/^-?(0|[1-9]\d{0,11})\.\d{2}$/;
const valid=v=>typeof v==="string"&&MONEY.test(v)&&v!=="-0.00";
const cents=v=>BigInt(v.replace(".",""));
const fail=error=>({error});
export function reconcileSharedOverhead(sourceAmount,lines,{anchorSiteId}={}){
 if(!valid(sourceAmount)||cents(sourceAmount)===0n||!Array.isArray(lines)||lines.length<2||lines.length>50)return fail("Nonzero signed source and 2–50 site shares required");
 if(typeof anchorSiteId!=="string"||!UUID.test(anchorSiteId))return fail("Valid source anchor site required");
 const source=cents(sourceAmount),seen=new Set(),shares=[];
 let sum=0n;
 for(const l of lines){
  if(!l||typeof l.siteId!=="string"||!UUID.test(l.siteId)||!valid(l.amount))return fail("Invalid site or exact-cent share");
  const siteId=l.siteId.toLowerCase(),amount=cents(l.amount);
  if(seen.has(siteId)||amount===0n||(source>0n)!==(amount>0n))return fail("Duplicate site, zero share or inconsistent credit sign");
  seen.add(siteId);sum+=amount;shares.push({siteId,amount:l.amount});
 }
 if(!seen.has(anchorSiteId.toLowerCase())||sum!==source)return fail("Shares must include the anchor site and reconcile exactly to the source");
 return {shares:shares.sort((a,b)=>a.siteId.localeCompare(b.siteId))};
}
