import {isIsoDate} from "./engine.js";
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(x);
const exact=(x,k)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===k.length&&k.every(y=>Object.hasOwn(x,y));
export const WORKSPACE_KINDS=["business","customer","site","contract","contract_site"];
export function workspaceRecordFields(input){
 if(!exact(input,["kind","parentId","relatedId","label"])||!WORKSPACE_KINDS.includes(input.kind))return null;
 const {kind,parentId,relatedId,label}=input;
 if(kind==="contract_site"){if(label!==null||!uuid(parentId)||!uuid(relatedId))return null;}
 else{
  if(typeof label!=="string"||!/^[A-Za-z][A-Za-z0-9 .&_-]{0,79}$/.test(label)||label.trim()!==label||/[0-9]([ ._-]*[0-9]){7,}/.test(label)||/\b(tfn|passport|medicare|password|payslip|bsb|bank account|credit card)\b/i.test(label))return null;
  if(kind==="business"?(parentId!==null||relatedId!==null):!uuid(parentId)||(kind==="contract"?!uuid(relatedId):relatedId!==null))return null;
 }
 return [kind,parentId,relatedId,label];
}
export function workspaceVersionFields(input){
 if(!exact(input,["versionId","periodStart","periodEnd","price","taxBasis","billingBasis","evidenceDigest"]))return null;
 const {versionId,periodStart,periodEnd,price,taxBasis,billingBasis,evidenceDigest}=input;
 if(!uuid(versionId)||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart||(Date.parse(periodEnd)-Date.parse(periodStart))/86400000>366||
 typeof price!=="string"||!/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(price)||!["gst_inclusive","gst_exclusive","no_gst"].includes(taxBasis)||
 !["monthly","weekly","fixed_period","per_service"].includes(billingBasis)||typeof evidenceDigest!=="string"||!/^[a-f0-9]{64}$/.test(evidenceDigest)||/^0+$/.test(evidenceDigest))return null;
 return [versionId,periodStart,periodEnd,price,taxBasis,billingBasis,evidenceDigest];
}
