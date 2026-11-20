import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,writeFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {deploymentProfile,databaseConfig,readSecret,validMfa} from "../server/deployment.js";
test("protected profile rejects missing prerequisites and TLS overrides",()=>{
 const dir=mkdtempSync(join(tmpdir(),"pp-config-"));
 try{
  const url=join(dir,"url"),key=join(dir,"key");
  writeFileSync(url,"postgres://app@db.invalid/profitpilot\n");writeFileSync(key,"a".repeat(64));
  const env={NODE_ENV:"production",PROFITPILOT_PROFILE:"protected",DATABASE_SSL:"true",DATABASE_URL_FILE:url,TENANT_CONTEXT_HMAC_SECRET_FILE:key,AUTH_MFA_ACR:"trusted-mfa",MALWARE_SCANNER_SOCKET:"/run/clamd/clamd.sock"};
  assert.throws(()=>deploymentProfile({NODE_ENV:"production"}));
  for(const k of ["DATABASE_SSL","DATABASE_URL_FILE","TENANT_CONTEXT_HMAC_SECRET_FILE","AUTH_MFA_ACR","MALWARE_SCANNER_SOCKET"])assert.throws(()=>deploymentProfile({...env,[k]:undefined}));
  assert.deepEqual(databaseConfig(env).ssl,{rejectUnauthorized:true});
  assert.equal(readSecret("TENANT_CONTEXT_HMAC_SECRET",env),"a".repeat(64));
  assert.throws(()=>readSecret("DATABASE_URL",{...env,DATABASE_URL:"ambiguous"}));
  writeFileSync(url,"postgres://app@db.invalid/profitpilot?sslmode=disable");
  assert.throws(()=>databaseConfig(env));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test("MFA checks trusted assurance and fresh signed authentication time",()=>{
 assert.ok(validMfa({acr:"strong",auth_time:100},"strong",500,900));
 for(const p of [{acr:"weak",auth_time:100},{acr:"strong"},{acr:"strong",auth_time:2000},{acr:"strong",auth_time:-1000}])assert.equal(validMfa(p,"strong",500,900),false);
});
