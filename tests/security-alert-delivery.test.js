import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,rmSync,readFileSync,chmodSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {initialAlertState,observeAlerts,signedAlert,verifyAlert,alertDestination,runAlertCycle} from "../scripts/security-alert-delivery.js";
const key="0123456789abcdef".repeat(4);
const snapshot={catalogVerified:true,counts:{activeTenantIncidents:1,temporarilyContainedActors:0,pendingOrRetryableScans:0,pendingOrProcessingPromotions:0},activeIncidents:[{tenantId:"confidential"}]};
test("alert schema excludes identifiers and signs exact bytes with timestamp and idempotency",()=>{
 const e=observeAlerts(initialAlertState(),snapshot).pending[0];
 assert.equal(e.category,"tenant_containment");assert.equal(e.state,"active");
 const wire=signedAlert(e,key,1000);
 assert.deepEqual(verifyAlert(wire.body,wire.headers,key,1000),e);
 assert.ok(!wire.body.includes("confidential"));
 assert.throws(()=>verifyAlert(wire.body.replace("active","cleared"),wire.headers,key,1000));
 assert.throws(()=>verifyAlert(wire.body,wire.headers,key,1301));
 assert.throws(()=>verifyAlert(wire.body,{...wire.headers,"Idempotency-Key":"wrong"},key,1000));
 for(const url of ["http://example.invalid/hook","https://user:pass@example.invalid/hook","https://example.invalid/hook?q=1","https://example.invalid/"]){assert.throws(()=>alertDestination({SECURITY_ALERT_ENABLED:"yes",SECURITY_ALERT_SIGNING_KEY:key,SECURITY_ALERT_WEBHOOK_URL:url}));}
 assert.throws(()=>alertDestination({SECURITY_ALERT_SIGNING_KEY:key,SECURITY_ALERT_WEBHOOK_URL:"https://example.invalid/hook"}));
});
test("failed notification is durably retried with same event ID and never silently cleared",async()=>{
 const dir=mkdtempSync(join(tmpdir(),"pp-alert-"));chmodSync(dir,0o700);
 try{
  const seen=[];
  await assert.rejects(()=>runAlertCycle({dir,read:async()=>snapshot,deliver:async e=>{seen.push(e);throw Error("unreachable");}}),/retry required/);
  const stored=JSON.parse(readFileSync(join(dir,"state.json"),"utf8"));
  assert.equal(stored.pending.length,1);assert.deepEqual(stored.pending[0],seen[0]);
  const result=await runAlertCycle({dir,read:async()=>snapshot,deliver:async e=>{seen.push(e);}});
  assert.deepEqual(result,{sent:1,remaining:0});assert.equal(seen[0].id,seen[1].id);
  assert.deepEqual(await runAlertCycle({dir,read:async()=>({...snapshot,catalogVerified:false}),deliver:async e=>{seen.push(e);}}),{sent:1,remaining:0});
  const final=JSON.parse(readFileSync(join(dir,"state.json"),"utf8"));
  assert.equal(final.states.tenant_containment,true);assert.equal(final.states.catalog_drift,true);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
