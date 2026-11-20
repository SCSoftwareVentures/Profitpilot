import {createHash} from "node:crypto";
export const FORMULA_VERSION="0.2.0";
export const MAX_EVIDENCE_LINES=2000;
const MAX_CENTS=99999999999999n;
export function decimalCents(value){
 if(typeof value!=="string"||! /^-?\d{1,12}(?:\.\d{1,2})?$/.test(value))throw new RangeError("Invalid exact decimal amount");
 const negative=value.startsWith("-");
 const [whole,fraction=""]=(negative?value.slice(1):value).split(".");
 const cents=BigInt(whole)*100n+BigInt(fraction.padEnd(2,"0"));
 return negative?-cents:cents;
}
export function formatCents(cents){
 if(typeof cents!=="bigint")throw new TypeError("Integer minor units required");
 const absolute=cents<0n?-cents:cents;
 return (cents<0n?"-":"")+(absolute/100n)+"."+String(absolute%100n).padStart(2,"0");
}
function bounded(cents){
 if(cents>MAX_CENTS||cents< -MAX_CENTS)throw new RangeError("Financial amount exceeds supported precision");
 return cents;
}
function divideRounded(n,d){
 if(d<=0n)throw new RangeError("Positive denominator required");
 const absolute=n<0n?-n:n;
 const rounded=absolute/d+(absolute%d*2n>=d?1n:0n);
 return n<0n?-rounded:rounded;
}
export function contributionTotals(revenues,costs){
 if(!Array.isArray(revenues)||!Array.isArray(costs)||!revenues.length||!costs.length||revenues.length>MAX_EVIDENCE_LINES||costs.length>MAX_EVIDENCE_LINES)throw new RangeError("Insufficient or excessive calculation evidence");
 const rev=bounded(revenues.reduce((s,v)=>s+decimalCents(v),0n));
 const cost=bounded(costs.reduce((s,v)=>{
  const n=decimalCents(v);if(n<0n)throw new RangeError("Negative payroll allocation");return s+n;
 },0n));
 const contribution=bounded(rev-cost);
 const margin=rev>0n?divideRounded(contribution*10000n,rev):null;
 const exact={revenue:formatCents(rev),deliveryCost:formatCents(cost),contribution:formatCents(contribution),marginPercent:margin===null?null:formatCents(margin)};
 return {revenue:Number(exact.revenue),deliveryCost:Number(exact.deliveryCost),contribution:Number(exact.contribution),
  marginPercent:margin===null||margin>MAX_CENTS||margin< -MAX_CENTS?null:Number(exact.marginPercent),exact};
}
export function canonicalSnapshot(value){
 if(value===null||typeof value==="string"||typeof value==="boolean")return JSON.stringify(value);
 if(typeof value==="number"&&Number.isSafeInteger(value))return JSON.stringify(value);
 if(Array.isArray(value))return "["+value.map(canonicalSnapshot).join(",")+"]";
 if(value&&typeof value==="object"&&Object.getPrototypeOf(value)===Object.prototype)return "{"+Object.keys(value).sort().map(k=>JSON.stringify(k)+":"+canonicalSnapshot(value[k])).join(",")+"}";
 throw new TypeError("Unsupported snapshot value");
}
export function snapshotDigest(snapshot){return createHash("sha256").update(canonicalSnapshot(snapshot),"utf8").digest("hex");}
