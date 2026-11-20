import {readFileSync,statSync} from "node:fs";

// Prototype is synthetic only. Protected mode enforces prerequisites, not release approval.
export function deploymentProfile(env=process.env){
 const mode=env.PROFITPILOT_PROFILE||(env.NODE_ENV==="production"?null:"prototype");
 if(!["prototype","protected"].includes(mode))throw new Error("Explicit PROFITPILOT_PROFILE required");
 const protectedMode=mode==="protected";
 const socketPath=env.MALWARE_SCANNER_SOCKET||null;
 const acr=env.AUTH_MFA_ACR||null;
 if(socketPath&&(!socketPath.startsWith("/")||socketPath.length>100||socketPath.includes("\0")))throw new Error("Scanner requires a bounded absolute Unix socket path");
 if(protectedMode&&(!socketPath||!acr||acr.length>200||env.DATABASE_SSL!=="true"||!env.DATABASE_URL_FILE||!env.TENANT_CONTEXT_HMAC_SECRET_FILE))
  throw new Error("Protected profile requires database TLS, mounted secrets, scanner and trusted MFA claim");
 return {mode,protectedMode,socketPath,acr};
}
export function readSecret(name,env=process.env){
 const path=env[name+"_FILE"];
 if(path){
  if(env[name])throw new Error("Ambiguous secret configuration: "+name);
  const stat=statSync(path);
  if(!stat.isFile()||stat.size<1||stat.size>8192)throw new Error("Invalid mounted secret: "+name);
  return readFileSync(path,"utf8").trim();
 }
 return env[name]||"";
}
export function databaseConfig(env=process.env){
 const profile=deploymentProfile(env),connectionString=readSecret("DATABASE_URL",env);
 if(profile.protectedMode){
  const url=new URL(connectionString);
  if(!["postgres:","postgresql:"].includes(url.protocol)||[...url.searchParams.keys()].some(k=>/^(ssl|sslmode|sslrootcert|sslcert|sslkey|uselibpqcompat)$/i.test(k)))
   throw new Error("Protected database URL may not override verified TLS settings");
 }
 return {connectionString,ssl:env.DATABASE_SSL==="true"?{rejectUnauthorized:true}:false};
}
export function validMfa(payload,requiredAcr,nowSeconds,maxAgeSeconds){
 if(!requiredAcr)return true;
 return payload.acr===requiredAcr&&Number.isSafeInteger(payload.auth_time)&&payload.auth_time<=nowSeconds+5&&nowSeconds-payload.auth_time<=maxAgeSeconds;
}
