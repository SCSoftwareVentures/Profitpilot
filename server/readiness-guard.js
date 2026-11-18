import {performance} from "node:perf_hooks";
// Coalesce concurrent checks, cache success briefly and fail closed on stale
// evidence, including DB unavailability. A check never extends last success
// on failure. This is a bounded detection interval, not instantaneous DDL
// fencing or a substitute for restricting database administrators.
export function createReadinessGuard(verify,{clock=()=>performance.now(),interval=15000,failureInterval=3000}={}){
 let pending,until=-Infinity,ready=false;
 async function check(){
  if(clock()<until)return ready;
  if(pending)return pending;
  pending=(async()=>{
   try{ready=await verify()===true;}catch{ready=false;}
   until=clock()+(ready?interval:failureInterval);
   return ready;
  })();
  try{return await pending;}finally{pending=undefined;}
 }
 async function middleware(_req,res,next){
  if(!await check()){res.set("Retry-After","3");return res.status(503).json({error:"Database security readiness unavailable"});}
  next();
 }
 return {check,middleware};
}
