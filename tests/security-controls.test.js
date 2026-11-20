import test from "node:test";
import assert from "node:assert/strict";
import {identityConfig,validSubject,validTokenLifetime} from "../server/auth.js";
import {allowedImportRows} from "../server/privacy.js";
const env={AUTH_ISSUER:"https://issuer.invalid/",AUTH_AUDIENCE:"api",AUTH_JWKS_URL:"https://issuer.invalid/jwks",NODE_ENV:"production"};
test("identity configuration rejects insecure, credential-bearing and non-test JWKS URLs",()=>{
 assert.equal(identityConfig(env).url.protocol,"https:");
 for(const url of ["http://issuer.invalid/jwks","http://127.0.0.1/jwks","https://user:secret@issuer.invalid/jwks","https://issuer.invalid/jwks#fragment"])assert.throws(()=>identityConfig({...env,AUTH_JWKS_URL:url}));
 assert.equal(identityConfig({...env,NODE_ENV:"test",AUTH_JWKS_URL:"http://127.0.0.1/jwks"}).url.protocol,"http:");
 assert.throws(()=>identityConfig({...env,NODE_ENV:"test",AUTH_JWKS_URL:"http://external.invalid/jwks"}));
});
test("identity subject and lifetime bounds",()=>{
 assert.ok(validSubject("provider|123"));for(const s of [""," ","a\nb","a\u0000b","x".repeat(256)])assert.equal(validSubject(s),false);
 assert.ok(validTokenLifetime({iat:100,exp:3700}));for(const p of [{iat:100},{exp:300},{iat:100,exp:99},{iat:100,exp:3701}])assert.equal(validTokenLifetime(p),false);
});
test("import minimisation rejects arbitrary fields, nested values and controls",()=>{
 assert.ok(allowedImportRows([{invoice_id:"001",site:"Site A",date:"2026-01-01",amount:"1.00"}],"customer_invoice"));
 assert.ok(allowedImportRows([{source_ref:"pay-1",amount:null}],"payroll"));
 for(const row of [{name:"Person"},{amount:{name:"Person"}},{amount:100},{site:"x\nY"},{site:"x".repeat(1001)},JSON.parse('{"__proto__":"x"}'),{}])assert.equal(allowedImportRows([row],"customer_invoice"),false);
 assert.equal(allowedImportRows([{invoice_id:"x"}],"__proto__"),false);
});
