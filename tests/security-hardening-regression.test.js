import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes,randomUUID,createHash,createHmac} from "node:crypto";
import {readFileSync} from "node:fs";
import {productionReleaseGate} from "../server/release-gate.js";
import {payrollConfirmationProof,securityWorkProof} from "../server/sensitive-operation-proof.js";
import {inspectInvoiceCsv} from "../server/secure-invoice-csv.js";

test("production denies all business operations even with purported approvals or enable flags",()=>{
 for(const env of [{NODE_ENV:"production"},{NODE_ENV:"production",RELEASE_APPROVED:"true",LIVE_MODE:"true",QUARANTINE_UPLOADS_ENABLED:"true"}]){
  let status,body,next=false;const response={set(){return this;},status(s){status=s;return this;},json(b){body=b;return this;}};
  productionReleaseGate(env)({},response,()=>{next=true;});
  assert.equal(next,false);assert.equal(status,503);assert.equal(body.code,"RELEASE_CLOSED");
 }
 let next=false;productionReleaseGate({NODE_ENV:"test"})({},null,()=>{next=true;});assert.equal(next,true);
 const source=readFileSync(new URL("../server/index.js",import.meta.url),"utf8");
 const gate=source.indexOf("app.use(productionReleaseGate());");
 assert.ok(gate>source.indexOf('app.get("/health"')&&gate<source.indexOf('app.use("/v1",authRequired())'));
 assert.ok(gate<source.indexOf('app.post("/v1/tenants/'));
});

test("server-generated payroll and work signatures match PostgreSQL canonical domain and bind exact scope",()=>{
 const now=1700000000,tenant=randomUUID(),id=randomUUID(),digest=createHash("sha256").update("synthetic-scope").digest("hex");
 const env={TENANT_CONTEXT_HMAC_SECRET:randomBytes(32).toString("hex"),TENANT_CONTEXT_HMAC_KEY_ID:"ci-proof"};
 const identity={subject:"synthetic-user",sessionId:"synthetic-session",mfa:true,authTime:now-10,issuedAt:now};
 const check=(proof,domain,fieldCount)=>{
  const fields=proof.slice(0,fieldCount),args=proof.slice(fieldCount,-1);
  assert.equal(args[2],createHash("sha256").update(identity.sessionId).digest("hex"));
  assert.equal(args[3],String(now+20));
  assert.match(args[4],/^[a-f0-9]{32}$/);
  assert.equal(proof.at(-1),createHmac("sha256",Buffer.from(env.TENANT_CONTEXT_HMAC_SECRET,"hex")).update([domain,...fields,identity.subject,...args].join("\n")).digest("hex"));
 };
 check(payrollConfirmationProof(tenant,id,digest,identity,env,now),"profitpilot-payroll-confirm-v1",3);
 check(securityWorkProof(tenant,id,"privacy_access",digest,"approve",identity,env,now),"profitpilot-security-work-v1",5);
 for(const bad of [{...identity,mfa:false},{...identity,authTime:now-301},{...identity,issuedAt:now+10},{...identity,sessionId:""},{...identity,subject:"bad\nsubject"}]){
  assert.throws(()=>payrollConfirmationProof(tenant,id,digest,bad,env,now),e=>e.status===403);
 }
 assert.throws(()=>securityWorkProof(tenant,id,"privacy_access",digest,"admin-bypass",identity,env,now));
 assert.throws(()=>payrollConfirmationProof(tenant,id,"0".repeat(64),identity,env,now));
});

test("private references use conservative data minimisation in CSV preflight",()=>{
 const header="invoice_id,site,date,amount\n";
 for(const value of ["date of birth","driver licence","medical record","api key","super member","account number","ＡＢＣ"]){
  assert.throws(()=>inspectInvoiceCsv(Buffer.from(header+"INV-1,"+value+",2026-01-01,10.00")));
 }
 assert.deepEqual(inspectInvoiceCsv(Buffer.from(header+"INV-1,Site A,2026-01-01,10.00")),{rowCount:1});
});
