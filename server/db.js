import pg from "pg";
import {createHmac,randomBytes,randomUUID} from "node:crypto";
const {Pool}=pg;
const production=process.env.NODE_ENV==="production";
const databaseSslEnabled=process.env.DATABASE_SSL==="true";
if(production&&!databaseSslEnabled){
 throw new Error("DATABASE_SSL=true is required in production; refusing an unencrypted PostgreSQL connection");
}
// node-postgres may replace explicit SSL options with connection-string SSL parameters.
if(databaseSslEnabled){
 const raw=process.env.DATABASE_URL;
 let url;
 try{url=new URL(raw);}catch{throw new Error("A valid PostgreSQL connection URL is required for TLS");}
 if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||url.hash)throw new Error("A valid PostgreSQL connection URL is required for TLS");
 // Allow no query parameters: URL options can override host, SSL and connection settings.
 if(url.search)throw new Error("Database TLS connection URL must not contain query parameters");
 if(process.env.NODE_TLS_REJECT_UNAUTHORIZED==="0")throw new Error("Global TLS certificate verification must not be disabled");
}
const ssl=databaseSslEnabled?{rejectUnauthorized:true}:false;
export const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl,max:10,idleTimeoutMillis:30000,connectionTimeoutMillis:5000,statement_timeout:10000,lock_timeout:3000,idle_in_transaction_session_timeout:10000});
export async function withTenant(tenantId,subject,fn,{repeatableRead=false}={}){
 if(typeof subject!=="string"||!subject)throw new Error("Verified identity subject is required for tenant context");
 const secret=process.env.TENANT_CONTEXT_HMAC_SECRET||"";
 const keyId=process.env.TENANT_CONTEXT_HMAC_KEY_ID||"primary";
 if(secret.length%2!==0||!/^[a-f0-9]{64,}$/i.test(secret))throw new Error("Tenant context signing secret must be at least 32 bytes of hexadecimal data");
 const expires=String(Math.floor(Date.now()/1000)+30);
 const nonce=randomBytes(16).toString("hex");
 const payload=[tenantId,subject,expires,nonce,keyId].join("\n");
 const signature=createHmac("sha256",Buffer.from(secret,"hex")).update(payload).digest("hex");
 const client=await pool.connect();
 try{
  await client.query(repeatableRead?"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY":"BEGIN");
  await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[tenantId,subject,expires,nonce,keyId,signature]);
  const result=await fn(client,{nonce});
  await client.query("COMMIT");
  return result;
 }catch(error){await client.query("ROLLBACK");throw error;}
 finally{client.release();}
}
export async function health(){const r=await pool.query("SELECT 1 AS ok");return r.rows[0].ok===1;}

// Only call from verified identity middleware or authenticated account routes.
// A proof is valid for the exact database transaction and backend, not another connection.
async function verifiedSessionOperation(action,{jti,subject,issuer,issuedAt,expiresAt,authTime},target=null,stepUpVerified=false){
 const keyId=process.env.TENANT_CONTEXT_HMAC_KEY_ID||"primary",secret=process.env.TENANT_CONTEXT_HMAC_SECRET||"";
 if(!/^[A-Za-z0-9._-]{1,128}$/.test(keyId)||secret.length%2!==0||!/^[a-f0-9]{64,256}$/i.test(secret))throw Error("Session signing configuration is invalid");
 const body=JSON.stringify({action,jti,subject,issuer,issuedAt,expiresAt,authTime:authTime??null,target,stepUpVerified});
 const client=await pool.connect();
 try{
  await client.query("BEGIN");
  const {rows:[ctx]}=await client.query("SELECT txid_current()::text AS tx,pg_backend_pid()::text AS pid");
  const proof=createHmac("sha256",Buffer.from(secret,"hex")).update(["profitpilot-session-op-v1",ctx.tx,ctx.pid,keyId,body].join("\n")).digest("hex");
  const result=await client.query("SELECT private.verified_session_operation($1,$2,$3) AS result",[keyId,body,proof]);
  await client.query("COMMIT");
  return result.rows[0]?.result;
 }catch(error){await client.query("ROLLBACK");throw error;}
 finally{client.release();}
}
export async function registerAndCheckAuthSession(identity){
 const result=await verifiedSessionOperation("admit",identity);
 return result?.accepted!==true;
}
export async function listAuthSessions(identity){
 const result=await verifiedSessionOperation("list",identity);
 if(result?.accepted!==true)throw Object.assign(new Error("Session unavailable"),{status:401});
 return result;
}
// Call only after requireStepUp has verified the signed MFA claims.
export async function revokeAllAuthSessions(identity){
 const result=await verifiedSessionOperation("revoke_all",identity,null,true);
 if(result?.accepted!==true)throw Object.assign(new Error("Session unavailable"),{status:401});
 return result;
}
export async function revokeAuthSession(jti,identity){
 const result=await verifiedSessionOperation("revoke",identity,jti);
 if(result?.accepted!==true)throw Object.assign(new Error("Session unavailable"),{status:401});
 return result.revoked===true;
}

 // Call only after requireStepUp has validated the provider's signed claims.
 // Domain separation and the transaction nonce prevent reusing a context signature as proof.
 export async function withPrivacyStepUp(membership,identity,requestId,action,fn){
  const {tenantId,userId}=membership;
  if(!Number.isSafeInteger(identity.authTime))throw Object.assign(new Error("Step-up required"),{status:403});
  return withTenant(tenantId,identity.subject,async(client,{nonce})=>{
   const payload=["profitpilot-privacy-step-up-v1",tenantId.toLowerCase(),userId.toLowerCase(),requestId.toLowerCase(),action,String(identity.authTime),nonce].join("\n");
   const proof=createHmac("sha256",Buffer.from(process.env.TENANT_CONTEXT_HMAC_SECRET,"hex")).update(payload).digest("hex");
   return fn(client,proof);
  });
 }

 // Only trusted server code can attest an exact audit event in its signed transaction.
 export async function appendAudit(client,member,action,objectType,objectId,reason,metadata={}){
  const {rows:[context]}=await client.query("SELECT current_setting('app.tenant_nonce',true) AS nonce");
  const body=JSON.stringify({id:randomUUID(),tenantId:member.tenantId.toLowerCase(),actorId:member.userId.toLowerCase(),action,objectType,objectId,reason,metadata});
  if(Buffer.byteLength(body,"utf8")>65536)throw new Error("Audit event exceeds bounded evidence size");
  const proof=createHmac("sha256",Buffer.from(process.env.TENANT_CONTEXT_HMAC_SECRET,"hex"))
   .update(["profitpilot-audit-write-v1",context.nonce,body].join("\n")).digest("hex");
  await client.query("SELECT private.append_verified_audit($1,$2)",[body,proof]);
 }
