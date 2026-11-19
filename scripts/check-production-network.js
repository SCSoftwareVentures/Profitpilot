import assert from "node:assert/strict";
import {createConnection} from "node:net";
import {performance} from "node:perf_hooks";
// Deliberately fixed loopback destination, bounded workload, no credentials
// and no ability to aim this acceptance tool at any real external service.
const port=8080,base="http://127.0.0.1:"+port;
function raw(request){
 return new Promise((resolve,reject)=>{
  let response="";const s=createConnection({host:"127.0.0.1",port});
  s.setTimeout(5000,()=>s.destroy(Error("Test socket timeout")));
  s.once("connect",()=>s.write(request));s.on("data",c=>{response+=c.toString();if(response.length>16384)s.destroy(Error("Oversized response"));});
  s.once("error",reject);s.once("end",()=>resolve(response));
 });
}
async function main(){
 const remaining=60000-Date.now()%60000;
 if(remaining<12000)await new Promise(resolve=>setTimeout(resolve,remaining+250));
 const started=performance.now();
 const probe=await fetch(base+"/health",{signal:AbortSignal.timeout(5000)});
 assert.equal(probe.status,200);assert.equal((await probe.json()).database,"connected");
 let rejected=0;
 for(const request of [
  "GET /v1/me HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer synthetic\r\nAuthorization: Bearer duplicate\r\nConnection: close\r\n\r\n",
  "POST /v1/me HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
  "GET /v1/me HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nConnection: close\r\n\r\nabcde",
  "GET http://localhost/v1/me HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
 ]){assert.match(await raw(request),/^HTTP\/1\.[01] 400\b/);rejected++;}
 // Unauthenticated traffic cannot extract data or bypass the global quota
 // using forged forwarding headers. Keep concurrency below admission limit
 // and allow bounded fail-closed 503 if backend admission is saturated.
 const statuses={};let leaked=0;const timings=[];
 for(let offset=0;offset<128;offset+=16){
  await Promise.all(Array.from({length:16},async(_,i)=>{
   const t=performance.now(),res=await fetch(base+"/v1/me",{headers:{"X-Forwarded-For":"198.51.100."+((offset+i)%250+1)},signal:AbortSignal.timeout(5000)});
   const body=await res.text();timings.push(performance.now()-t);
   statuses[res.status]=(statuses[res.status]||0)+1;
   if(res.status===200||/"(?:subject|email)"\s*:/.test(body))leaked++;
   assert.ok([401,429,503].includes(res.status),"Expected authentication denial or bounded throttling");
   assert.match(res.headers.get("cache-control")||"",/no-store/);
  }));
 }
 assert.equal(leaked,0);
 assert.ok(statuses[429]>0,"Distributed quota must throttle forged IP rotation");
 const during=await fetch(base+"/health",{signal:AbortSignal.timeout(5000)});
 assert.ok([200,429,503].includes(during.status));
 timings.sort((a,b)=>a-b);
 process.stdout.write(JSON.stringify({event:"synthetic_production_network_acceptance",rejectedMalformed:rejected,requests:128,statuses,leaked,p95Ms:Math.round(timings[Math.ceil(timings.length*.95)-1]),elapsedMs:Math.round(performance.now()-started)})+"\n");
}
main().catch(()=>{process.stderr.write("Synthetic production network acceptance failed.\n");process.exitCode=1;});
