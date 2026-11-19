import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import pg from "pg";
import {verifyDatabaseReadiness} from "../server/database-readiness.js";
import {acceptedAccessToken,issuerAttestedMfa} from "../server/auth.js";

test("production rejects ID tokens and requires issuer-specific MFA assurance",()=>{
 const env={NODE_ENV:"production",AUTH_ACCESS_TOKEN_PROFILE:"rfc9068",AUTH_MFA_ACR:"urn:reviewed:mfa"};
 assert.equal(acceptedAccessToken({typ:"at+jwt"},{},env),true);
 assert.equal(acceptedAccessToken({typ:"JWT"},{},env),false);
 assert.equal(acceptedAccessToken({typ:"at+jwt"},{token_use:"id"},env),false);
 assert.equal(acceptedAccessToken({typ:"application/at+jwt"},{},env),true);
 assert.equal(acceptedAccessToken({typ:"JWT"},{token_use:"access"},{...env,AUTH_ACCESS_TOKEN_PROFILE:"token_use_access"}),true);
 assert.equal(acceptedAccessToken({typ:"JWT"},{token_use:"id"},{...env,AUTH_ACCESS_TOKEN_PROFILE:"token_use_access"}),false);
 assert.equal(acceptedAccessToken({typ:"at+jwt"},{},{...env,AUTH_ACCESS_TOKEN_PROFILE:""}),false);
 assert.equal(issuerAttestedMfa({amr:["pwd","mfa"],acr:"urn:reviewed:mfa"},env),true);
 assert.equal(issuerAttestedMfa({amr:["pwd","mfa"]},env),false);
 assert.equal(issuerAttestedMfa({amr:["mfa"],acr:"other"},env),false);
 assert.equal(issuerAttestedMfa({amr:["pwd"],acr:"urn:reviewed:mfa"},env),false);
});
const url=process.env.DATABASE_SSL_TEST_URL,ca=process.env.DATABASE_SSL_CA;
test("live database readiness refuses incorrect key, missing key and non-TLS connections",{skip:!url||!ca,timeout:30000},async()=>{
 const tls=new pg.Pool({connectionString:url,ssl:{ca,rejectUnauthorized:true}});
 const plain=new pg.Pool({connectionString:url,ssl:false});
 const env={...process.env,NODE_ENV:"production"};
 try{
  assert.equal(await verifyDatabaseReadiness(tls,env),true);
  await assert.rejects(()=>verifyDatabaseReadiness(tls,{...env,TENANT_CONTEXT_HMAC_SECRET:randomBytes(32).toString("hex")}),/signing key readiness/i);
  await assert.rejects(()=>verifyDatabaseReadiness(tls,{...env,TENANT_CONTEXT_HMAC_KEY_ID:"missing-"+randomBytes(6).toString("hex")}),/signing key readiness/i);
  await assert.rejects(()=>verifyDatabaseReadiness(plain,env),/readiness checks failed|SSL|encryption/i);
 }finally{await Promise.all([tls.end(),plain.end()]);}
});
