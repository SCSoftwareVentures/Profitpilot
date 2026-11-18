import {X509Certificate} from "node:crypto";

// Production startup configuration validation. No secrets are logged.
export function validateProductionSecrets(env=process.env){
 if(env.NODE_ENV!=="production")return;
 if(env.NODE_TLS_REJECT_UNAUTHORIZED==="0")throw new Error("Production TLS verification cannot be disabled");
 if(env.QUARANTINE_UPLOADS_ENABLED==="true"||env.QUARANTINE_WORKER_ENABLED==="true")throw new Error("Production quarantine workflow is not approved");
 if(env.PGOPTIONS||env.PGSERVICE||env.PGSERVICEFILE)throw new Error("Production cannot inherit PostgreSQL connection overrides");
 const secret=env.TENANT_CONTEXT_HMAC_SECRET||"";
 if(!/^[0-9a-f]{64,128}$/i.test(secret)||secret.length%2!==0||new Set(secret.toLowerCase()).size<12)throw new Error("Production tenant signing key must be at least 32 random bytes encoded as hex");
 const keyId=env.TENANT_CONTEXT_HMAC_KEY_ID||"primary";
 if(!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(keyId))throw new Error("Invalid tenant signing key ID");
 const rateSecret=env.RATE_LIMIT_HASH_SECRET||"";
 if(!/^[0-9a-f]{64}$/i.test(rateSecret)||new Set(rateSecret.toLowerCase()).size<12||rateSecret.toLowerCase()===secret.toLowerCase())throw new Error("Production rate-limit key must be an independent 32-byte hex secret");
 if(!env.DATABASE_URL)throw new Error("Production DATABASE_URL is required");
 let url;
 try{url=new URL(env.DATABASE_URL);}catch{throw new Error("Production DATABASE_URL is invalid");}
 if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||!url.username||!url.password)throw new Error("Production database connection requires a valid PostgreSQL URL and credentials");
 if(url.search||url.hash)throw new Error("Database URL must not override verified connection configuration");
 const password=decodeURIComponent(url.password);
 if(password.length<24||/replace-with|password|changeme/i.test(password)||[secret,rateSecret].some(k=>k.toLowerCase()===password.toLowerCase()))throw new Error("Production database password must be independent and not a placeholder");
 if(decodeURIComponent(url.username)!=="profitpilot_app")throw new Error("Production database connection must use the restricted application role");
 if(env.DATABASE_SSL!=="true")throw new Error("Production database TLS must be enabled");
 if(!env.DATABASE_SSL_CA?.trim())throw new Error("Production database TLS trust anchor is required");
 const pem=env.DATABASE_SSL_CA.trim();
 const certificates=pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)||[];
 if(!certificates.length||pem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,"").trim())throw new Error("Production database CA must contain only PEM certificates");
 try{for(const value of certificates){const c=new X509Certificate(value);if(!c.ca||Date.parse(c.validFrom)>Date.now()||Date.parse(c.validTo)<=Date.now())throw Error();}}catch{throw new Error("Production database CA must contain currently valid CA certificates");}
 if(!env.AUTH_ISSUER||!env.AUTH_AUDIENCE||!env.AUTH_JWKS_URL)throw new Error("Production authentication configuration is incomplete");
 if(!["rfc9068","token_use_access"].includes(env.AUTH_ACCESS_TOKEN_PROFILE))throw new Error("Explicit production access-token profile required");
 if(typeof env.AUTH_MFA_ACR!=="string"||!env.AUTH_MFA_ACR.trim()||env.AUTH_MFA_ACR.length>255||/\p{C}/u.test(env.AUTH_MFA_ACR))throw new Error("Explicit issuer-attested production MFA ACR required");
 if(typeof env.AUTH_AUDIENCE!=="string"||env.AUTH_AUDIENCE.length>255||!env.AUTH_AUDIENCE.trim()||/\p{C}/u.test(env.AUTH_AUDIENCE))throw new Error("Invalid production token audience");
 for(const [name,value] of [["AUTH_ISSUER",env.AUTH_ISSUER],["AUTH_JWKS_URL",env.AUTH_JWKS_URL]]){
  let endpoint;
  try{endpoint=new URL(value);}catch{throw new Error(name+" must be a valid HTTPS URL");}
  if(endpoint.protocol!=="https:"||endpoint.username||endpoint.password||endpoint.hash||endpoint.search)throw new Error(name+" must use a verified plain HTTPS endpoint");
 }
}
