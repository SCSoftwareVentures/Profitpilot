import {openSync,fstatSync,readSync,closeSync,constants} from "node:fs";

// Protected deployments may explicitly allow only canonical HTTPS browser origins.
// Empty allowlist denies cross-origin browser requests; it is not a wildcard.
export function protectedCorsOrigins(raw){
 if(raw===undefined||raw===null||raw==="")return [];
 if(typeof raw!=="string"||raw.length>2048)throw Error("Invalid protected CORS configuration");
 const origins=raw.split(",").map(x=>x.trim());
 if(origins.length>8||origins.some(x=>!x)||new Set(origins).size!==origins.length)
  throw Error("Invalid or duplicate protected CORS origins");
 for(const origin of origins){
  let url;
  try{url=new URL(origin);}catch{throw Error("Invalid protected CORS origin");}
  if(origin.includes("*")||url.protocol!=="https:"||url.origin!==origin||
    url.username||url.password||url.search||url.hash||url.pathname!=="/"||
    !url.hostname||["localhost","127.0.0.1","0.0.0.0","[::1]"].includes(url.hostname)||
    url.hostname.endsWith(".localhost"))
   throw Error("Protected CORS requires exact HTTPS origins");
 }
 return origins;
}

// Prototype is synthetic only. Protected mode enforces prerequisites, not release approval.
export function deploymentProfile(env=process.env){
 const mode=env.PROFITPILOT_PROFILE||(env.NODE_ENV==="production"?null:"prototype");
 if(!["prototype","protected"].includes(mode))throw new Error("Explicit PROFITPILOT_PROFILE required");
 const protectedMode=mode==="protected";
 if(protectedMode&&env.NODE_ENV!=="production")
  throw Error("Protected profile requires NODE_ENV=production");
 const corsOrigins=protectedMode?protectedCorsOrigins(env.CORS_ORIGIN):
  (env.CORS_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean);
 const scannerEnabled=env.MALWARE_SCAN_MODE==="clamav";
 const acr=env.AUTH_MFA_ACR||null;
 if(protectedMode&&(!scannerEnabled||!acr||acr.length>200||env.DATABASE_SSL!=="true"||!env.DATABASE_URL_FILE||!env.TENANT_CONTEXT_HMAC_SECRET_FILE))
  throw new Error("Protected profile requires database TLS, mounted secrets, scanner and trusted MFA claim");
 return {mode,protectedMode,scannerEnabled,acr,corsOrigins};
}
export function readSecret(name,env=process.env){
 const path=env[name+"_FILE"];
 if(path){
  if(env[name])throw new Error("Ambiguous secret configuration: "+name);
  // Open once and check/read the same descriptor; path replacement cannot switch the file mid-check.
  // Never follow a final-component symlink, including in synthetic tests.
  // In the protected profile require owner-only mounted-secret access.
  const fd=openSync(path,constants.O_RDONLY|constants.O_NONBLOCK|constants.O_NOFOLLOW);
  try{
   const stat=fstatSync(fd);
   if(!stat.isFile()||stat.size<1||stat.size>8192)throw new Error("Invalid mounted secret: "+name);
   if(deploymentProfile(env).protectedMode&&(stat.mode&0o077)!==0)
    throw new Error("Protected mounted secret must have owner-only permissions: "+name);
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
