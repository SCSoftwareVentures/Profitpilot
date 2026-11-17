import test from "node:test";
import assert from "node:assert/strict";
import {EventEmitter} from "node:events";
import {createSecurityTelemetry,securityTelemetryMiddleware} from "../server/security-telemetry.js";

test("bounded category-only aggregates emit one threshold alert per window",()=>{
 let now=120000;
 const events=[];
 const t=createSecurityTelemetry({clock:()=>now,emit:e=>events.push(e)});
 for(let i=0;i<100;i++)assert.equal(t.record("authentication_denied"),true);
 assert.equal(t.record("token=secret&user=person"),false);
 assert.equal(t.record("constructor"),false);
 assert.equal(events.length,1);
 assert.equal(events[0].count,20);
 now=180000;t.flush();
 assert.equal(events[1].event,"security_window");
 assert.deepEqual(events[1].counts,{authentication_denied:100});
 for(let i=0;i<20;i++)t.record("authentication_denied");
 assert.equal(events.length,3);
 now=120000;assert.equal(t.record("authentication_denied"),false);
 assert.equal(JSON.stringify(events).includes("secret"),false);
});
test("middleware never emits identity, headers, path parameters, body or query; closed responses counted once",()=>{
 let now=120000;
 const events=[];
 const t=createSecurityTelemetry({clock:()=>now,emit:e=>events.push(e)});
 const middleware=securityTelemetryMiddleware(t);
 const req={path:"/v1/tenants/private-tenant/security/permissions",method:"GET",route:{path:"/v1/tenants/:tenantId/security/permissions"},identity:{subject:"private-subject"},headers:{authorization:"Bearer secret"},body:{card:"private-data"},query:{q:"private-query"}};
 const r=new EventEmitter();r.statusCode=200;
 middleware(req,r,()=>{});r.emit("finish");r.emit("close");
 const bad=new EventEmitter();bad.statusCode=401;
 middleware(req,bad,()=>{});bad.emit("finish");bad.emit("close");
 const aborted=new EventEmitter();middleware(req,aborted,()=>{});aborted.emit("close");
 const unrelated=new EventEmitter();unrelated.statusCode=500;
 middleware({path:"/public"},unrelated,()=>{});unrelated.emit("finish");
 now=180000;t.flush();
 assert.deepEqual(events[0].counts,{security_audit_access:1,authentication_denied:1,request_aborted:1});
 assert.equal(/private-|Bearer|secret|tenantId/.test(JSON.stringify(events)),false);
});
test("invalid buckets and unavailable telemetry sinks do not expose data or block requests",()=>{
 assert.throws(()=>createSecurityTelemetry({windowMs:0}),/Invalid telemetry window/);
 const t=createSecurityTelemetry({clock:()=>0,emit:()=>{throw Error("unavailable");}});
 assert.doesNotThrow(()=>{for(let i=0;i<100;i++)t.record("service_error");});
});
