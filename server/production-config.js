// Production startup configuration validation. No secrets are logged.
export function validateProductionSecrets(env=process.env){
 if(env.NODE_ENV!=="production")return;
 const secret=env.TENANT_CONTEXT_HMAC_SECRET||"";
 if(!/^[0-9a-f]{64,}$/i.test(secret)||secret.length%2!==0)throw new Error("Production tenant signing key must be at least 32 random bytes encoded as hex");
 if(!env.DATABASE_URL)throw new Error("Production DATABASE_URL is required");
 let url;
 try{url=new URL(env.DATABASE_URL);}catch{throw new Error("Production DATABASE_URL is invalid");}
 if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||!url.username||!url.password)throw new Error("Production database connection requires a valid PostgreSQL URL and credentials");
 if(env.DATABASE_SSL!=="true")throw new Error("Production database TLS must be enabled");
 if(!env.DATABASE_SSL_CA?.trim())throw new Error("Production database TLS trust anchor is required");
 if(!env.AUTH_ISSUER||!env.AUTH_AUDIENCE||!env.AUTH_JWKS_URL)throw new Error("Production authentication configuration is incomplete");
 for(const [name,value] of [["AUTH_ISSUER",env.AUTH_ISSUER],["AUTH_JWKS_URL",env.AUTH_JWKS_URL]]){
  let endpoint;
  try{endpoint=new URL(value);}catch{throw new Error(name+" must be a valid HTTPS URL");}
  if(endpoint.protocol!=="https:")throw new Error(name+" must use HTTPS");
 }
}
