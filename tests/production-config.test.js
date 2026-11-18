import test from "node:test";
import assert from "node:assert/strict";
import {createHash,X509Certificate} from "node:crypto";
import {rootCertificates} from "node:tls";
import {validateProductionSecrets} from "../server/production-config.js";
const sample=label=>createHash("sha256").update(label).digest("hex");
const ca=rootCertificates.find(value=>{const c=new X509Certificate(value);return c.ca&&Date.parse(c.validFrom)<=Date.now()&&Date.parse(c.validTo)>Date.now();});
const valid={NODE_ENV:"production",RATE_LIMIT_HASH_SECRET:sample("rate"),TENANT_CONTEXT_HMAC_SECRET:sample("signing"),DATABASE_URL:"postgresql://profitpilot_app:"+sample("db")+"@db.example.invalid/profitpilot",DATABASE_SSL:"true",DATABASE_SSL_CA:ca,AUTH_ACCESS_TOKEN_PROFILE:"rfc9068",AUTH_MFA_ACR:"urn:ci:mfa",AUTH_ISSUER:"https://identity.example.invalid/",AUTH_AUDIENCE:"profitpilot-api",AUTH_JWKS_URL:"https://identity.example.invalid/jwks"};
test("valid production configuration passes",()=>assert.doesNotThrow(()=>validateProductionSecrets(valid)));
test("development is not blocked by production checks",()=>assert.doesNotThrow(()=>validateProductionSecrets({NODE_ENV:"test"})));
for(const [name,change] of [
 ["disabled TLS verification",{NODE_TLS_REJECT_UNAUTHORIZED:"0"}],
 ["placeholder signing secret",{TENANT_CONTEXT_HMAC_SECRET:"a".repeat(64)}],
 ["invalid CA",{DATABASE_SSL_CA:"not a certificate"}],
 ["missing access token profile",{AUTH_ACCESS_TOKEN_PROFILE:""}],
 ["missing MFA ACR",{AUTH_MFA_ACR:""}],
 ["database options override",{PGOPTIONS:"-c statement_timeout=0"}],
 ["production quarantine enabled",{QUARANTINE_UPLOADS_ENABLED:"true"}],
 ["missing signing secret",{TENANT_CONTEXT_HMAC_SECRET:""}],
 ["missing rate limit secret",{RATE_LIMIT_HASH_SECRET:""}],
 ["reused signing key",{RATE_LIMIT_HASH_SECRET:valid.TENANT_CONTEXT_HMAC_SECRET}],
 ["administrator runtime login",{DATABASE_URL:"postgresql://profitpilot_admin:secret@db.example.invalid/profitpilot"}],
 ["non-TLS URL override",{DATABASE_URL:"postgresql://profitpilot_app:secret@db.example.invalid/profitpilot?options=-c%20statement_timeout=0"}],
 ["issuer credentials",{AUTH_ISSUER:"https://user:pass@identity.example.invalid/"}],
 ["TLS URL override",{DATABASE_URL:"postgresql://profitpilot_app:secret@db.example.invalid/profitpilot?sslmode=disable"}],
 ["short signing secret",{TENANT_CONTEXT_HMAC_SECRET:"a".repeat(32)}],
 ["missing database credentials",{DATABASE_URL:"postgresql://db.example.invalid/profitpilot"}],
 ["TLS disabled",{DATABASE_SSL:"false"}],
 ["missing CA",{DATABASE_SSL_CA:""}],
 ["insecure issuer",{AUTH_ISSUER:"http://identity.example.invalid/"}],
 ["insecure JWKS",{AUTH_JWKS_URL:"http://identity.example.invalid/jwks"}]
])test("production rejects "+name,()=>assert.throws(()=>validateProductionSecrets({...valid,...change})));
