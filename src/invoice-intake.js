const exact=(x,keys)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
export const invoiceDigest=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
export function invoiceIntakeFields(b){
 if(!exact(b,["controlTotal","rowCount","evidenceDigest"])||typeof b.controlTotal!=="string"||!/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(b.controlTotal)||b.controlTotal==="0.00"||
 !Number.isSafeInteger(b.rowCount)||b.rowCount<1||b.rowCount>200||!invoiceDigest(b.evidenceDigest))return null;
 return [b.controlTotal,b.rowCount,b.evidenceDigest];
}
