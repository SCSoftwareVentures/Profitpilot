import {createHash} from "node:crypto";
import {isIsoDate,money} from "./engine.js";

// Pure, versioned planning only. Never writes to the database or approves a run.
export const PAYROLL_PLAN_VERSION = "payroll-reconciliation-1.0.0";
const keyPattern=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const opaque=value=>typeof value==="string"&&value===value.trim()&&keyPattern.test(value);
const object=value=>value!==null&&typeof value==="object"&&!Array.isArray(value);
const exact=(value,keys)=>object(value)&&Object.keys(value).length===keys.length&&keys.every(k=>Object.hasOwn(value,k));
const currency=value=>typeof value==="string"&&value.length===3&&/^[A-Z]{3}$/.test(value);
const cmp=(a,b)=>a<b?-1:a>b?1:0;
const sha=value=>createHash("sha256").update(value,"utf8").digest("hex");
const cents=value=>{
  if(typeof value!=="string"||value!==value.trim()||!/^(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,2})?$/.test(value))return null;
  const canonical=money(value);
  return canonical===null?null:BigInt(canonical.replace(".",""));
};
const decimal=n=>String(n/100n)+"."+String(n%100n).padStart(2,"0");
const buckets=["direct","approved_allocated","non_site","excluded"];
const isSite=bucket=>bucket==="direct"||bucket==="approved_allocated";
const held=(code,index)=>({version:PAYROLL_PLAN_VERSION,status:"held",requiresHumanConfirmation:true,errors:[index===undefined?{code}:{code,index}],proposal:null});

/**
 * Input uses pre-minimised, synthetic or authorised opaque identifiers only.
 * No employee columns, arbitrary notes, banking data or source payloads.
 * Evidence references are syntactically checked, not authenticated by this planner.
 * Actual approval and source/tenant/site verification belong to a trusted service.
 */
export function planPayrollReconciliation(input){
  if(!exact(input,["pool","sourceRows","allocations"]))return held("INVALID_INPUT_SHAPE");
  const {pool,sourceRows,allocations}=input;
  if(!exact(pool,["poolRef","periodStart","periodEnd","currency","total"])||
    !opaque(pool.poolRef)||!isIsoDate(pool.periodStart)||!isIsoDate(pool.periodEnd)||
    pool.periodEnd<pool.periodStart||!currency(pool.currency)||cents(pool.total)===null)
    return held("INVALID_POOL");
  if(!Array.isArray(sourceRows)||sourceRows.length<1||sourceRows.length>10000||
    !Array.isArray(allocations)||allocations.length>50000)return held("INVALID_BATCH_SIZE");

  const sources=new Map();
  let sourceTotal=0n;
  for(let i=0;i<sourceRows.length;i++){
    const row=sourceRows[i];
    if(!exact(row,["sourceRowKey","amount","currency","rowSha256"])||
      !opaque(row.sourceRowKey)||!currency(row.currency)||cents(row.amount)===null)
      return held("INVALID_SOURCE_ROW",i);
    if(row.currency!==pool.currency)return held("MIXED_CURRENCY",i);
    if(sources.has(row.sourceRowKey))return held("DUPLICATE_SOURCE_ROW",i);
    const amount=cents(row.amount),canonical=decimal(amount);
    if(row.rowSha256!==sha([row.sourceRowKey,canonical,row.currency].join("\n")))
      return held("SOURCE_DIGEST_MISMATCH",i);
    sources.set(row.sourceRowKey,{sourceRowKey:row.sourceRowKey,amount:canonical,currency:row.currency,rowSha256:row.rowSha256,remaining:amount});
    sourceTotal+=amount;
  }
  if(sourceTotal!==cents(pool.total))return held("POOL_TOTAL_MISMATCH");

  const totals=Object.fromEntries([...buckets,"unallocated"].map(k=>[k,0n]));
  const sites=new Map(),seen=new Set(),lines=[];
  for(let i=0;i<allocations.length;i++){
    const line=allocations[i];
    if(!exact(line,["sourceRowKey","bucket","siteRef","amount","evidenceRef"])||
      !opaque(line.sourceRowKey)||!buckets.includes(line.bucket)||!opaque(line.evidenceRef)||
      (isSite(line.bucket)?!opaque(line.siteRef):line.siteRef!==null))
      return held("INVALID_ALLOCATION",i);
    const amount=cents(line.amount);
    if(amount===null||amount===0n)return held("INVALID_ALLOCATION_AMOUNT",i);
    const source=sources.get(line.sourceRowKey);
    if(!source)return held("UNKNOWN_SOURCE_ROW",i);
    const unique=JSON.stringify([line.sourceRowKey,line.bucket,line.siteRef]);
    if(seen.has(unique))return held("DUPLICATE_ALLOCATION_BUCKET",i);
    seen.add(unique);
    if(amount>source.remaining)return held("SOURCE_OVERALLOCATED",i);
    source.remaining-=amount;
    totals[line.bucket]+=amount;
    if(isSite(line.bucket))sites.set(line.siteRef,(sites.get(line.siteRef)||0n)+amount);
    lines.push({sourceRowKey:line.sourceRowKey,bucket:line.bucket,siteRef:line.siteRef,amount:decimal(amount),evidenceRef:line.evidenceRef});
  }
  const sortedSources=[...sources.values()].sort((a,b)=>cmp(a.sourceRowKey,b.sourceRowKey));
  for(const source of sortedSources){
    if(source.remaining>0n){
      totals.unallocated+=source.remaining;
      lines.push({sourceRowKey:source.sourceRowKey,bucket:"unallocated",siteRef:null,amount:decimal(source.remaining),evidenceRef:null});
    }
  }
  lines.sort((a,b)=>cmp(a.sourceRowKey,b.sourceRowKey)||cmp(a.bucket,b.bucket)||cmp(a.siteRef??"",b.siteRef??""));
  const attributed=totals.direct+totals.approved_allocated;
  const coverageBasisPoints=sourceTotal===0n?null:Number(attributed*10000n/sourceTotal);
  const proposal={
    pool:{poolRef:pool.poolRef,periodStart:pool.periodStart,periodEnd:pool.periodEnd,currency:pool.currency,total:decimal(sourceTotal)},
    sourceRows:sortedSources.map(({remaining,...row})=>row),
    lines,
    totals:Object.fromEntries(Object.entries(totals).map(([k,v])=>[k,decimal(v)])),
    siteTotals:[...sites.entries()].sort(([a],[b])=>cmp(a,b)).map(([siteRef,amount])=>({siteRef,amount:decimal(amount)})),
    // Coverage is floor-rounded basis points; it is an allocation statistic, not proof.
    attributionCoverageBasisPoints:coverageBasisPoints
  };
  return {
    version:PAYROLL_PLAN_VERSION,
    status:totals.unallocated===0n?"pending_review":"needs_allocation",
    requiresHumanConfirmation:true,
    errors:[],
    proposal,
    proposalSha256:sha(JSON.stringify([PAYROLL_PLAN_VERSION,proposal]))
  };
}
