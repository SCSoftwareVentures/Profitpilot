import {openSync,fstatSync,readSync,closeSync,constants} from "node:fs";

// Prototype is synthetic only. Protected mode enforces prerequisites, not release approval.
export function deploymentProfile(env=process.env){
 const mode=env.PROFITPILOT_PROFILE||(env.NODE_ENV==="production"?null:"prototype");
 if(!["prototype","protected"].includes(mode))throw new Error("Explicit PROFITPILOT_PROFILE required");
 const protectedMode=mode==="protected";
 const scannerEnabled=env.MALWARE_SCAN_MODE==="clamav";
 const acr=env.AUTH_MFA_ACR||null;
 if(protectedMode&&(!scannerEnabled||!acr||acr.length>200||env.DATABASE_SSL!=="true"||!env.DATABASE_URL_FILE||!env.TENANT_CONTEXT_HMAC_SECRET_FILE))
  throw new Error("Protected profile requires database TLS, mounted secrets, scanner and trusted MFA claim");
 return {mode,protectedMode,scannerEnabled,acr};
}
export function readSecret(name,env=process.env){
 const path=env[name+"_FILE"];
 if(path){
  if(env[name])throw new Error("Ambiguous secret configuration: "+name);
  // Open once and check/read the same descriptor; path replacement cannot switch the file mid-check.
  const fd=openSync(path,constants.O_RDONLY|constants.O_NONBLOCK);
  try{
   const stat=fstatSync(fd);
   if(!stat.isFile()||stat.size<1||stat.size>8192)throw new Error("Invalid mounted secret: "+name);
   const bytes=Buffer.alloc(8193);let offset=0;
   while(offset<bytes.byteLength){
    const n=readSync(fd,bytes,offset,bytes.byteLength-offset,null);
    if(n===0)break;
    offset+=n;
   }
   if(offset<1||offset>8192)throw new Error("Invalid mounted secret: "+name);
   const value=new TextDecoder("utf-8",{fatal:true}).decode(bytes.subarray(0,offset)).trim();
   if(!value)throw new Error("Empty mounted secret: "+name);
   return value;
  }finally{closeSync(fd);}
 }
 return env[name]||"";
}
export function databaseConfig(env=process.env){
 const profile=deploymentProfile(env),connectionString=readSecret("DATABASE_URL",env);
 if(profile.protectedMode){
  const url=new URL(connectionString);
  if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||!url.pathname||url.pathname==="/"||url.hash||url.search)
   throw new Error("Protected database URL requires a host/database and no query or fragment overrides");
 }
 return {connectionString,ssl:env.DATABASE_SSL==="true"?{rejectUnauthorized:true}:false};
}
export function validMfa(payload,requiredAcr,nowSeconds,maxAgeSeconds){
 if(!requiredAcr)return true;
 return payload.acr===requiredAcr&&Number.isSafeInteger(payload.auth_time)&&payload.auth_time>0&&payload.auth_time<=nowSeconds+5&&nowSeconds-payload.auth_time<=maxAgeSeconds;
}
