import test from "node:test";
import assert from "node:assert/strict";
import {EventEmitter} from "node:events";
import {createSecurityMonitor} from "../server/security-monitor.js";
test("monitor counts denial, abuse, failure, timing and aborted requests without storing sensitive request details",()=>{
 let now=0;const reports=[];
 const monitor=createSecurityMonitor({clock:()=>now,sink:e=>reports.push(e)});
 function request(status,{slow=false,aborted=false,contained=false}={}){
  const res=new EventEmitter();res.statusCode=status;res.locals={actorContained:contained};res.writableFinished=!aborted;
  monitor.middleware({headers:{authorization:"SECRET_TOKEN"},url:"/private/customer",body:{name:"PRIVATE_DATA"}},res,()=>{});
  if(slow)now+=2000;
  if(!aborted)res.emit("finish");
  res.emit("close");
 }
 request(200);request(401);request(403);request(429,{contained:true});request(400);request(503,{slow:true});request(500);request(200,{aborted:true});
 const result=monitor.flush();
 assert.deepEqual(result,{event:"api_security_interval",requests:8,success:1,authDenied:1,roleDenied:1,rateLimited:1,actorContained:1,otherClientError:1,unavailable:1,serverError:1,aborted:1,slow:1});
 assert.doesNotMatch(JSON.stringify(reports),/SECRET_TOKEN|PRIVATE_DATA|private\/customer/);
 assert.equal(monitor.flush().requests,0);
});
