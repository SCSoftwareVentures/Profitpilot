// Connected payroll client for a reviewed same-origin workspace.
// The caller supplies short-lived access tokens from its identity provider.
// No storage, automatic mutation retries, token logging or demo-data fallback.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MONEY=/^(0|[1-9][0-9]{0,11})(?:\.[0-9]{1,2})?$/;
const BUCKETS=new Set(["direct","approved_allocated","non_site","excluded"]);
const id=(value)=>{if(typeof value!=="string"||!UUID.test(value))throw new TypeError("Invalid resource ID");return value;};
const text=(value,min,max)=>{if(typeof value!=="string"||value.trim().length<min||value.trim().length>max)throw new TypeError("Invalid reason or evidence reference");return value.trim();};
const money=(value)=>{if(typeof value!=="string"||!MONEY.test(value)||!/[1-9]/.test(value))throw new TypeError("Positive AUD decimal string required");return value;};
const int=(value,min,max)=>{if(!Number.isInteger(value)||value<min||value>max)throw new TypeError("Invalid row number or pagination");return value;};
const messages={400:"Invalid request.",401:"Sign in again.",403:"Access denied or fresh multifactor authentication required.",404:"Record not found.",409:"Record state changed or conflicts. Refresh before retrying.",422:"Review the source and reconciliation evidence.",429:"Request limit reached. Try again later."};
export class PayrollRequestError extends Error {
 constructor(status,write=false){super(messages[status]||(write?"Request outcome is uncertain. Check server state before retrying.":"Payroll service unavailable."));this.name="PayrollRequestError";this.status=status;}
}
export function createPayrollClient({getAccessToken,fetchImpl=globalThis.fetch}={}){
 if(typeof getAccessToken!=="function"||typeof fetchImpl!=="function")throw new TypeError("Authenticated transport required");
 async function request(path,{body,signal,fresh=false}={}){
  if(signal?.aborted)throw new DOMException("Aborted","AbortError");
  const token=await getAccessToken({fresh,signal});
  if(typeof token!=="string"||!/^[A-Za-z0-9._~-]{1,8192}$/.test(token))throw new PayrollRequestError(401);
  const headers={Accept:"application/json",Authorization:"Bearer "+token};
  if(body!==undefined)headers["Content-Type"]="application/json";
  let response;
  try{response=await fetchImpl(path,{method:body===undefined?"GET":"POST",headers,body:body===undefined?undefined:JSON.stringify(body),cache:"no-store",credentials:"omit",redirect:"error",referrerPolicy:"no-referrer",signal});}
  catch{throw new PayrollRequestError(0,body!==undefined);}
  if(!response.ok)throw new PayrollRequestError(response.status,body!==undefined);
  try{return await response.json();}catch{throw new PayrollRequestError(0,body!==undefined);}
 }
 const root=tenant=>"/v1/tenants/"+id(tenant);
 const batch=(tenant,batchId)=>root(tenant)+"/imports/"+id(batchId);
 const pool=(tenant,poolId)=>root(tenant)+"/payroll/pools/"+id(poolId)+"/allocations";
 const allocation=(tenant,poolId,allocationId)=>pool(tenant,poolId)+"/"+id(allocationId);
 return Object.freeze({
  async review(tenant,batchId,{offset=0,limit=50,signal}={}){
   const result=await request(batch(tenant,batchId)+"/review?offset="+int(offset,0,9999999)+"&limit="+int(limit,1,100),{signal});
   if(result?.sourceType!=="payroll"||result.batchId!==batchId)throw new PayrollRequestError(422);
   return result;
  },
  decide(tenant,batchId,rowNumber,{decision,reason,signal}={}){
   if(!["accepted","rejected"].includes(decision))throw new TypeError("Explicit review decision required");
   return request(batch(tenant,batchId)+"/payroll/rows/"+int(rowNumber,1,9999999)+"/decision",{body:{decision,reason:text(reason,3,1000)},fresh:true,signal});
  },
  reconcile(tenant,batchId,{declaredTotal,sourceReference,reason,signal}={}){
   return request(batch(tenant,batchId)+"/payroll/pool",{body:{declaredTotal:money(declaredTotal),sourceReference:text(sourceReference,3,120),reason:text(reason,3,1000)},fresh:true,signal});
  },
  draft(tenant,poolId,{lines,reason,signal}={}){
   if(!Array.isArray(lines)||lines.length<1||lines.length>100)throw new TypeError("One to 100 allocation lines required");
   const safeLines=lines.map(line=>{
    if(!line||!BUCKETS.has(line.bucketType))throw new TypeError("Invalid bucket");
    const attributable=["direct","approved_allocated"].includes(line.bucketType);
    if(!attributable&&line.siteId!=null)throw new TypeError("Non-site bucket must not include a site");
    return {bucketType:line.bucketType,siteId:attributable?id(line.siteId):null,amount:money(line.amount),sourceReference:text(line.sourceReference,3,120)};
   });
   return request(pool(tenant,poolId),{body:{lines:safeLines,reason:text(reason,3,1000)},signal});
  },
  readAllocation(tenant,poolId,allocationId,{signal}={}){
   return request(allocation(tenant,poolId,allocationId),{signal});
  },
  confirmDeliveryExpense(tenant,matchId,{reason,costCategory,payrollOverlapReviewed,duplicateExpenseReviewed,signal}={}){
   if(!["supplier","subcontractor","other_delivery"].includes(costCategory)||payrollOverlapReviewed!==true||duplicateExpenseReviewed!==true)throw new TypeError("Explicit cost category and overlap checks required");
   return request(root(tenant)+"/matches/"+id(matchId)+"/decision",{body:{decision:"confirmed",reason:text(reason,3,2000),costCategory,payrollOverlapReviewed:true,duplicateExpenseReviewed:true},fresh:true,signal});
  },
  createContributionReport(tenant,{contractId,siteId,periodStart,periodEnd,signal}={}){
   if(![periodStart,periodEnd].every(v=>typeof v==="string"&&/^\d{4}-\d{2}-\d{2}$/.test(v))||periodEnd<periodStart)throw new TypeError("Valid service period required");
   return request(root(tenant)+"/calculations",{body:{contractId:id(contractId),siteId:id(siteId),periodStart,periodEnd},signal});
  },
  readContributionReport(tenant,runId,{signal}={}){
   return request(root(tenant)+"/calculations/"+id(runId),{signal});
  },
  confirm(tenant,poolId,allocationId,{reason,acknowledged=false,signal}={}){
   if(acknowledged!==true)throw new TypeError("Explicit confirmation required");
   return request(allocation(tenant,poolId,allocationId)+"/confirm",{body:{reason:text(reason,3,1000)},fresh:true,signal});
  }
 });
}
