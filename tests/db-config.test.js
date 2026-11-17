import test from "node:test";
import assert from "node:assert/strict";
import {databaseSslConfig} from "../server/db-config.js";

test("production database configuration fails closed when TLS is disabled",()=>{
  assert.throws(()=>databaseSslConfig({NODE_ENV:"production",DATABASE_SSL:"false"}),/require DATABASE_SSL=true/);
  assert.throws(()=>databaseSslConfig({NODE_ENV:"production"}),/require DATABASE_SSL=true/);
});

test("TLS configuration verifies server certificates and accepts an explicit CA",()=>{
  assert.deepEqual(databaseSslConfig({NODE_ENV:"production",DATABASE_SSL:"true"}),{rejectUnauthorized:true});
  const ca="-----BEGIN CERTIFICATE-----\nsynthetic-test-ca\n-----END CERTIFICATE-----";
  assert.deepEqual(databaseSslConfig({NODE_ENV:"production",DATABASE_SSL:"true",DATABASE_SSL_CA:ca}),{rejectUnauthorized:true,ca});
});

test("non-production local development may explicitly use plaintext database transport",()=>{
  assert.equal(databaseSslConfig({NODE_ENV:"development",DATABASE_SSL:"false"}),false);
  assert.equal(databaseSslConfig({NODE_ENV:"test"}),false);
});

test("a CA cannot be silently ignored when TLS is disabled",()=>{
  assert.throws(()=>databaseSslConfig({NODE_ENV:"development",DATABASE_SSL:"false",DATABASE_SSL_CA:"pem"}),/cannot be set while database TLS is disabled/);
});
