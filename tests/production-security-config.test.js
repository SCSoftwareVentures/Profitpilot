import test from "node:test";
import assert from "node:assert/strict";
import {assertProductionConfig,validRuntimeRole} from "../server/production-config.js";
import {releaseCleanConnection} from "../server/pool-safety.js";
const valid={NODE_ENV:"production",DATABASE_SSL:"true",DATABASE_URL:"postgresql://profitpilot_app:synthetic@db.example.invalid/profitpilot",AUTH_ISSUER:"https://identity.example.invalid/",AUTH_JWKS_URL:"https://identity.example.invalid/.well-known/jwks.json",AUTH_AUDIENCE:"profitpilot-api",AUTH_STEP_UP_ACR:"urn:profitpilot:mfa",CORS_ORIGIN:"https://app.example.invalid",TENANT_CONTEXT_HMAC_SECRET:"ab".repeat(32)};
test("production fails closed for insecure, incomplete or mixed operator/application configuration",()=>{
 assert.doesNotThrow(()=>assertProductionConfig(valid));
 assert.doesNotThrow(()=>assertProductionConfig({NODE_ENV:"test"}));
 const bad=[
 {DATABASE_SSL:"false"},{NODE_TLS_REJECT_UNAUTHORIZED:"0"},{DATABASE_URL:"postgresql://postgres:synthetic@db.example.invalid/profitpilot"},
 {DATABASE_URL:valid.DATABASE_URL+"?sslmode=disable"},{AUTH_ISSUER:"http://identity.example.invalid"},{AUTH_JWKS_URL:"https://user:pass@id.example.invalid/jwks"},
 {AUTH_AUDIENCE:""},{AUTH_STEP_UP_ACR:""},{AUTH_STEP_UP_MAX_AGE_SECONDS:"3600"},
 {CORS_ORIGIN:"*"},{CORS_ORIGIN:"http://app.example.invalid"},{CORS_ORIGIN:"https://app.example.invalid/path"},{CORS_ORIGIN:"https://app.example.invalid,https://app.example.invalid"},
 {TENANT_CONTEXT_HMAC_SECRET:"synthetic-secret"},{TENANT_CONTEXT_HMAC_KEY_ID:"bad key"},{TEST_ADMIN_DATABASE_URL:"fixture"},
 {PRIVACY_CHECKPOINT_KEY:"operator-secret"},{POSTGRES_ADMIN_PASSWORD:"operator-password"},{ENABLE_SYNTHETIC_PAYROLL_UI:"true"}
 ];
 for(const patch of bad)assert.throws(()=>assertProductionConfig({...valid,...patch}),error=>error.message.startsWith("Invalid production security configuration:")&&!/operator-secret|synthetic-secret|user:pass/.test(error.message));
});
test("runtime role refuses all elevated capabilities and unknown states",()=>{
 const role={role:"profitpilot_app",sessionRole:"profitpilot_app",canLogin:true,superuser:false,bypassRls:false,createRole:false,createDb:false,replication:false,inherit:false,otherMembership:false,databaseCreate:false,databaseTemp:false,publicCreate:false,privateCreate:false};
 assert.equal(validRuntimeRole(role),true);
 for(const flag of ["superuser","bypassRls","createRole","createDb","replication","inherit","otherMembership","databaseCreate","databaseTemp","publicCreate","privateCreate"]){
  assert.equal(validRuntimeRole({...role,[flag]:true}),false,flag);
  assert.equal(validRuntimeRole({...role,[flag]:undefined}),false,flag);
 }
 assert.equal(validRuntimeRole({...role,sessionRole:"profitpilot_admin"}),false);
 assert.equal(validRuntimeRole({...role,role:"profitpilot_admin"}),false);
});
test("pooled connections discard session state and destroy uncertain connections",async()=>{
 const events=[];
 const client={query:async x=>events.push(x),release:e=>events.push(e)};
 await releaseCleanConnection(client);
 assert.deepEqual(events,["DISCARD ALL",undefined]);
 const broken=Error("rollback failed");
 events.length=0;await releaseCleanConnection(client,broken);
 assert.deepEqual(events,[broken]);
 events.length=0;
 client.query=async()=>{throw Error("reset failed");};
 await releaseCleanConnection(client);
 assert.equal(events[0].message,"reset failed");
});
