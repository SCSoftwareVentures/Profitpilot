const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const digest=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
const money=x=>typeof x==="string"&&/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(x)&&x!=="0.00";
export function sharedCostFields(kind,source,input){
 if(!["payroll","overhead","business_overhead"].includes(kind)||typeof source!=="string"||!uuid.test(source)||!input||typeof input!=="object"||Object.keys(input).length!==2||!digest(input.evidenceDigest)||!Array.isArray(input.shares)||input.shares.length<1||input.shares.length>100)return null;
 const shares=[];let prev="";
 for(const line of input.shares){
  const business=kind==="business_overhead",n=business?4:3;
  if(!Array.isArray(line)||line.length!==n||!money(line[n-1]))return null;
  const ids=line.slice(0,n-1);if(!ids.every(x=>x===null)&&!ids.every(x=>typeof x==="string"&&uuid.test(x)))return null;
  const key=business?(ids[0]??"~")+","+(ids[1]??"~"):ids[0]??"~";if(key<=prev)return null;prev=key;shares.push([...line]);
 }
 return {shares,evidence:input.evidenceDigest,canonical:["shared-cost-v1",kind,source,input.evidenceDigest,...shares.map(x=>x.map(v=>v??"~").join(","))].join("\n")};
}

export function sharedCostCorrectionFields(kind,source,input){
 if(!input||typeof input!=="object"||Object.keys(input).length!==3||typeof input.replacesOrderId!=="string"||!uuid.test(input.replacesOrderId))return null;
 const {replacesOrderId,...rest}=input,f=sharedCostFields(kind,source,rest);if(!f)return null;
 return {...f,replaces:replacesOrderId,canonical:["shared-cost-correction-v1",kind,source,replacesOrderId,f.evidence,...f.shares.map(x=>x.map(v=>v??"~").join(","))].join("\n")};
}
