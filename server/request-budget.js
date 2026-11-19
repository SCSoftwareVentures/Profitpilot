// Conservative limits for the current prototype; revisit with measured workloads.
export const MAX_BATCH_ROWS=1000;
export const MAX_JSON_NODES=4096;
export const MAX_JSON_DEPTH=8;
export function jsonWithinBudget(body){
 if(body===undefined)return true;
 let seen=0;
 const pending=[{value:body,depth:0}];
 while(pending.length){
  const {value,depth}=pending.pop();
  if(++seen>MAX_JSON_NODES||depth>MAX_JSON_DEPTH)return false;
  if(typeof value==="string"){if(/[\u0000\uD800-\uDFFF]/u.test(value))return false;continue;}
  if(typeof value==="number"&&!Number.isFinite(value))return false;
  if(value===null||typeof value!=="object")continue;
  for(const k of Object.keys(value)){
   if(k==="__proto__"||k==="constructor"||k==="prototype"||/[\u0000\uD800-\uDFFF]/u.test(k))return false;
   if(pending.length+seen>=MAX_JSON_NODES)return false;
   pending.push({value:value[k],depth:depth+1});
  }
 }
 return true;
}
export function enforceJsonBudget(req,res,next){
 if(!jsonWithinBudget(req.body))return res.status(400).json({error:"Request JSON exceeds safe structure limits or contains unsupported characters"});
 next();
}
export function createRequestAdmission(limit=32){
 if(!Number.isSafeInteger(limit)||limit<1||limit>256)throw new Error("Invalid admission limit");
 let active=0;
 return (req,res,next)=>{
  if(active>=limit){res.set("Retry-After","5");return res.status(503).json({error:"Request capacity temporarily unavailable"});}
  active++;
  let released=false;
  const release=()=>{if(!released){released=true;active--;}};
  res.once("finish",release);res.once("close",release);
  next();
 };
}
// Keep work permits until promises settle, even if the HTTP connection closes.
export function createWorkBudget(limit=16){
 if(!Number.isSafeInteger(limit)||limit<1||limit>256)throw new Error("Invalid work limit");
 let active=0;
 return async work=>{
  if(active>=limit)throw Object.assign(new Error("Database work capacity unavailable"),{status:503});
  active++;
  try{return await work();}finally{active--;}
 };
}
