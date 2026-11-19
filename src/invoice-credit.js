const digest=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
export function invoiceCreditFields(x){if(!x||typeof x!=="object"||Array.isArray(x)||Object.keys(x).length!==3||!digest(x.creditReferenceDigest)||!digest(x.evidenceDigest)||typeof x.amount!=="string"||!/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(x.amount)||x.amount==="0.00")return null;return [x.creditReferenceDigest,x.amount,x.evidenceDigest];}

const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
export function invoiceCreditReversalFields(x){if(!x||typeof x!=="object"||Array.isArray(x)||Object.keys(x).length!==4||typeof x.reversesOrderId!=="string"||!uuid.test(x.reversesOrderId))return null;const {reversesOrderId,...rest}=x,f=invoiceCreditFields(rest);return f?[reversesOrderId,...f]:null;}

export function sharedInvoiceCreditFields(x){
 if(!x||typeof x!=="object"||Array.isArray(x)||Object.keys(x).length!==5||typeof x.allocationOrderId!=="string"||!uuid.test(x.allocationOrderId)||!Array.isArray(x.shares)||x.shares.length<1||x.shares.length>100)return null;
 const {allocationOrderId,shares,...rest}=x,fields=invoiceCreditFields(rest);if(!fields)return null;
 let prev="",sum=0n;for(const v of shares){if(!Array.isArray(v)||v.length!==4||(!v.slice(0,3).every(y=>y===null)&&!v.slice(0,3).every(y=>typeof y==="string"&&uuid.test(y)))||typeof v[3]!=="string"||!/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(v[3])||v[3]==="0.00")return null;
 const key=(v[0]??"~")+","+(v[1]??"~");if(key<=prev)return null;prev=key;sum+=BigInt(v[3].replace(".",""));}
 if(sum!==BigInt(fields[1].replace(".","")))return null;return {allocation:allocationOrderId,fields,shares};
}
