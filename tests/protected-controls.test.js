import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,writeFileSync,rmSync,chmodSync,symlinkSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {deploymentProfile,databaseConfig,readSecret,validMfa} from "../server/deployment.js";
test("protected profile rejects missing prerequisites and TLS overrides",()=>{
 const dir=mkdtempSync(join(tmpdir(),"pp-config-"));
 try{
  const url=join(dir,"url"),key=join(dir,"key");
  writeFileSync(url,"postgres://app@db.invalid/profitpilot\n",{mode:0o600});writeFileSync(key,"a".repeat(64),{mode:0o600});
  const env={NODE_ENV:"production",PROFITPILOT_PROFILE:"protected",DATABASE_SSL:"true",DATABASE_URL_FILE:url,TENANT_CONTEXT_HMAC_SECRET_FILE:key,AUTH_MFA_ACR:"trusted-mfa",MALWARE_SCAN_MODE:"clamav"};
  assert.throws(()=>deploymentProfile({NODE_ENV:"production"}));
  for(const k of ["DATABASE_SSL","DATABASE_URL_FILE","TENANT_CONTEXT_HMAC_SECRET_FILE","AUTH_MFA_ACR","MALWARE_SCAN_MODE"])assert.throws(()=>deploymentProfile({...env,[k]:undefined}));
  assert.deepEqual(databaseConfig(env).ssl,{rejectUnauthorized:true});
  assert.equal(readSecret("TENANT_CONTEXT_HMAC_SECRET",env),"a".repeat(64));
  chmodSync(key,0o644);
  assert.throws(()=>readSecret("TENANT_CONTEXT_HMAC_SECRET",env),/owner-only permissions/);
  chmodSync(key,0o600);
  const link=join(dir,"linked-key");symlinkSync(key,link);
  assert.throws(()=>readSecret("TENANT_CONTEXT_HMAC_SECRET",{...env,TENANT_CONTEXT_HMAC_SECRET_FILE:link}));
  assert.throws(()=>readSecret("DATABASE_URL",{...env,DATABASE_URL:"ambiguous"}));
  for(const invalid of ["postgres://app@db.invalid/profitpilot?sslmode=disable","postgres://app@db.invalid/profitpilot?options=-c%20statement_timeout=0","postgres://app@db.invalid/profitpilot?host=other.invalid","postgres://app@db.invalid/profitpilot#x","postgres://app@db.invalid/"]){writeFileSync(url,invalid);assert.throws(()=>databaseConfig(env));}
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test("MFA checks trusted assurance and fresh signed authentication time",()=>{
 assert.ok(validMfa({acr:"strong",auth_time:100},"strong",500,900));
 for(const p of [{acr:"weak",auth_time:100},{acr:"strong"},{acr:"strong",auth_time:2000},{acr:"strong",auth_time:-1000}])assert.equal(validMfa(p,"strong",500,900),false);
});

test("mounted secret input is bounded and must be a nonempty regular UTF-8 file",()=>{
 const dir=mkdtempSync(join(tmpdir(),"pp-secret-"));
 try{
  const path=join(dir,"secret"),env={TEST_SECRET_FILE:path};
  for(const value of [""," ","x".repeat(8193),Buffer.from([0xff])]){
   writeFileSync(path,value);
   assert.throws(()=>readSecret("TEST_SECRET",env));
  }
  writeFileSync(path,"x".repeat(8192));
  assert.equal(readSecret("TEST_SECRET",env).length,8192);
  assert.throws(()=>readSecret("TEST_SECRET",{TEST_SECRET_FILE:dir}));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
