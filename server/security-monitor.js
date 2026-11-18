import {performance} from "node:perf_hooks";
import {createSecurityAlertPolicy} from "./security-alert-policy.js";

function newCounters(){return {requests:0,success:0,authDenied:0,roleDenied:0,rateLimited:0,actorContained:0,otherClientError:0,unavailable:0,serverError:0,aborted:0,slow:0};}
// Aggregate only fixed enumerated fields. Never record headers, URLs,
// identity, IP, body, user-controlled labels or exception contents.
export function createSecurityMonitor({clock=()=>performance.now(),sink=event=>process.stdout.write(JSON.stringify(event)+"\n")}={}){
 let counters=newCounters(), interval;
 const evaluateAlerts=createSecurityAlertPolicy();
 function middleware(req,res,next){
  const start=clock();
  let recorded=false;
  function complete(aborted){
   if(recorded)return;
   recorded=true;
   counters.requests++;
   if(clock()-start>=2000)counters.slow++;
   if(aborted){counters.aborted++;return;}
   const status=res.statusCode;
   if(status===401)counters.authDenied++;
   else if(status===403)counters.roleDenied++;
   else if(status===429){counters.rateLimited++;if(res.locals?.actorContained===true)counters.actorContained++;}
   else if(status===503)counters.unavailable++;
   else if(status>=500)counters.serverError++;
   else if(status>=400)counters.otherClientError++;
   else counters.success++;
  }
  res.once("finish",()=>complete(false));
  res.once("close",()=>complete(!res.writableFinished));
  next();
 }
 function flush(){
  const report={event:"api_security_interval",...counters};
  counters=newCounters();
  sink(report);
  for(const alert of evaluateAlerts(report))sink(alert);
  return report;
 }
 function start(){
  if(interval)return;
  interval=setInterval(()=>{try{flush();}catch{/* Monitoring failures must not crash API */}},60000);
  interval.unref();
 }
 function stop(){if(interval)clearInterval(interval);interval=undefined;}
 return {middleware,flush,start,stop};
}
