const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const keys=["sourceRowKey","bucket","siteId","amount","evidenceRef"];
export function canonicalAllocationMapping(pool,lines){
 if(typeof pool!=="string"||!UUID.test(pool)||!Array.isArray(lines)||lines.length>400)return null;
 const out=["payroll-allocation-build-v1",pool],seen=new Set();
 for(const l of lines){
  if(l===null||typeof l!=="object"||Array.isArray(l)||Object.keys(l).length!==5||!keys.every(k=>Object.hasOwn(l,k))||
  typeof l.sourceRowKey!=="string"||!/^ppr_[a-f0-9]{64}$/.test(l.sourceRowKey)||/^ppr_0+$/.test(l.sourceRowKey)||
  !["approved_allocated","non_site","excluded"].includes(l.bucket)||
  (l.bucket==="approved_allocated"?(typeof l.siteId!=="string"||!UUID.test(l.siteId)):l.siteId!==null)||
  typeof l.amount!=="string"||!/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(l.amount)||l.amount==="0.00"||
  typeof l.evidenceRef!=="string"||!/^ev_[a-f0-9]{60}$/.test(l.evidenceRef)||/^ev_0+$/.test(l.evidenceRef))return null;
  const k=[l.sourceRowKey,l.bucket,l.siteId??""].join(",");
  if(seen.has(k))return null;seen.add(k);
  out.push(k+","+l.amount+","+l.evidenceRef);
 }
 return out.join("\n");
}
