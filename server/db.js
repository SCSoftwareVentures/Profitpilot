import pg from "pg";
import {createHmac,createHash,randomBytes,randomUUID} from "node:crypto";
import {validRuntimeRole} from "./production-config.js";
import {releaseCleanConnection} from "./pool-safety.js";
import {currentRequestIdentity} from "./request-identity.js";
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
 if(typeof subject!=="string"||!subject||subject.length>512||subject.trim()!==subject||/[\x00-\x1f\x7f]/.test(subject))throw new Error("Verified identity subject is required for tenant context");
 if(typeof tenantId!=="string"||!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId))throw new Error("Valid tenant identifier required");
 tenantId=tenantId.toLowerCase();
 const requestIdentity=currentRequestIdentity();
 if((production&&!requestIdentity)||(requestIdentity&&requestIdentity.subject!==subject))
  throw Object.assign(new Error("Verified request identity mismatch"),{status:401});
 const secret=process.env.TENANT_CONTEXT_HMAC_SECRET||"";
 const keyId=process.env.TENANT_CONTEXT_HMAC_KEY_ID||"primary";
 if(!/^[A-Za-z0-9._-]{1,128}$/.test(keyId)||secret.length%2!==0||!/^[a-f0-9]{64,256}$/i.test(secret))throw new Error("Tenant context signing configuration is invalid");
 const client=await pool.connect();
 let discard;
 try{
  await client.query(repeatableRead?"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY":"BEGIN");
  const {rows:[ctx]}=await client.query("SELECT txid_current()::text AS tx,pg_backend_pid()::text AS pid");
  const expires=String(Math.floor(Date.now()/1000)+30);
  const nonce=randomBytes(16).toString("hex");
  const payload=["profitpilot-tenant-context-v2",ctx.tx,ctx.pid,tenantId,subject,expires,nonce,keyId].join("\n");
  const signature=createHmac("sha256",Buffer.from(secret,"hex")).update(payload).digest("hex");
  await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[tenantId,subject,expires,nonce,keyId,signature]);
  if(requestIdentity){
   const body=JSON.stringify({tenantId,subject:requestIdentity.subject,issuer:requestIdentity.issuer,jti:requestIdentity.jti,issuedAt:requestIdentity.issuedAt,expiresAt:requestIdentity.expiresAt,authTime:requestIdentity.authTime??null});
   const proof=createHmac("sha256",Buffer.from(secret,"hex")).update(["profitpilot-tenant-session-v1",ctx.tx,ctx.pid,nonce,body].join("\n")).digest("hex");
   const {rows:[session]}=await client.query("SELECT private.assert_admitted_tenant_session($1,$2) AS accepted",[body,proof]);
   if(session?.accepted!==true)throw Object.assign(new Error("Session revoked or unavailable"),{status:401});
  }
  const result=await fn(client,{nonce});
  await client.query("COMMIT");
  return result;
 }catch(error){
  try{await client.query("ROLLBACK");}catch(rollbackError){discard=rollbackError;}
  throw error;
 }finally{await releaseCleanConnection(client,discard);}
}
export async function assertRuntimeDatabaseRole(){
 const {rows:[role]}=await pool.query(`
 SELECT r.rolname AS role,session_user AS "sessionRole",r.rolcanlogin AS "canLogin",
  r.rolsuper AS superuser,r.rolbypassrls AS "bypassRls",r.rolcreaterole AS "createRole",
  r.rolcreatedb AS "createDb",r.rolreplication AS replication,r.rolinherit AS inherit,
  EXISTS(SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid) AS "otherMembership",
  has_database_privilege(current_user,current_database(),'CREATE') AS "databaseCreate",
  has_database_privilege(current_user,current_database(),'TEMPORARY') AS "databaseTemp",
  has_schema_privilege(current_user,'public','CREATE') AS "publicCreate",
  has_schema_privilege(current_user,'private','CREATE') AS "privateCreate"
 FROM pg_roles r WHERE r.rolname=current_user`);
 if(!validRuntimeRole(role))throw Error("Restricted database runtime role verification failed");
 return true;
}
export async function health(){const r=await pool.query("SELECT 1 AS ok");return r.rows[0].ok===1;}

// Only call from verified identity middleware or authenticated account routes.
// A proof is valid for the exact database transaction and backend, not another connection.
async function verifiedSessionOperation(action,{jti,subject,issuer,issuedAt,expiresAt,authTime},target=null,stepUpVerified=false){
 const keyId=process.env.TENANT_CONTEXT_HMAC_KEY_ID||"primary",secret=process.env.TENANT_CONTEXT_HMAC_SECRET||"";
 if(!/^[A-Za-z0-9._-]{1,128}$/.test(keyId)||secret.length%2!==0||!/^[a-f0-9]{64,256}$/i.test(secret))throw Error("Session signing configuration is invalid");
 const body=JSON.stringify({action,jti,subject,issuer,issuedAt,expiresAt,authTime:authTime??null,target,stepUpVerified});
 const client=await pool.connect();
 let discard;
 try{
  await client.query("BEGIN");
  const {rows:[ctx]}=await client.query("SELECT txid_current()::text AS tx,pg_backend_pid()::text AS pid");
  const proof=createHmac("sha256",Buffer.from(secret,"hex")).update(["profitpilot-session-op-v1",ctx.tx,ctx.pid,keyId,body].join("\n")).digest("hex");
  const result=await client.query("SELECT private.verified_session_operation($1,$2,$3) AS result",[keyId,body,proof]);
  await client.query("COMMIT");
  return result.rows[0]?.result;
 }catch(error){
  try{await client.query("ROLLBACK");}catch(rollbackError){discard=rollbackError;}
  throw error;
 }finally{await releaseCleanConnection(client,discard);}
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

 // The signed proof is bound to the resource, action, actor and transaction nonce.
 export async function withFinancialStepUp(membership,identity,target,action,fn){
  const now=Math.floor(Date.now()/1000),maxAge=Number(process.env.AUTH_STEP_UP_MAX_AGE_SECONDS??300);
  if(!Number.isInteger(maxAge)||maxAge<30||maxAge>900||!Number.isSafeInteger(identity?.authTime)||identity.authTime>now||now-identity.authTime>maxAge||!process.env.AUTH_STEP_UP_ACR||identity.acr!==process.env.AUTH_STEP_UP_ACR||!identity.amr?.includes("mfa"))
   throw Object.assign(new Error("Recent financial MFA required"),{status:403});
  return withPrivacyStepUp(membership,identity,target,"financial:"+action,async(client,proof)=>{
   await client.query("SELECT set_config('app.financial_auth_time',$1,true),set_config('app.financial_proof',$2,true)",[String(identity.authTime),proof]);
   return fn(client);
  });
 }

 // Payload read capabilities are generated only inside a verified tenant transaction.
 export async function sourceReadProof(client,membership,identity,batchId,purpose){
  if(!["compare","validate","payroll_reconcile","invoice_prepare","reconcile"].includes(purpose))throw Error("Invalid source read purpose");
  let authTime=0;
  if(!["compare","validate"].includes(purpose)){
   const now=Math.floor(Date.now()/1000),maxAge=Number(process.env.AUTH_STEP_UP_MAX_AGE_SECONDS??300);
   if(!Number.isInteger(maxAge)||maxAge<30||maxAge>900||!Number.isSafeInteger(identity?.authTime)||identity.authTime>now||now-identity.authTime>maxAge||!process.env.AUTH_STEP_UP_ACR||identity.acr!==process.env.AUTH_STEP_UP_ACR||!identity.amr?.includes("mfa"))throw Object.assign(new Error("Recent source read MFA required"),{status:403});
   authTime=identity.authTime;
  }
  const {rows:[ctx]}=await client.query("SELECT current_setting('app.tenant_nonce',true) AS nonce");
  const body=["profitpilot-privacy-step-up-v1",membership.tenantId.toLowerCase(),membership.userId.toLowerCase(),batchId.toLowerCase(),"source_read:"+purpose,String(authTime),ctx.nonce].join("\n");
  const proof=createHmac("sha256",Buffer.from(process.env.TENANT_CONTEXT_HMAC_SECRET,"hex")).update(body).digest("hex");
  return [membership.tenantId,batchId,purpose,authTime,proof];
 }

 export async function stageSourceRows(client,membership,identity,batchId,rows,{csv=false,checksum=null}={}){
  const body=JSON.stringify({mode:csv?"csv":"json",rows,checksum:csv?checksum:null});
  let authTime=0;
  if(csv){
   const now=Math.floor(Date.now()/1000),maxAge=Number(process.env.AUTH_STEP_UP_MAX_AGE_SECONDS??300);
   if(!Number.isInteger(maxAge)||maxAge<30||maxAge>900||!Number.isSafeInteger(identity?.authTime)||identity.authTime>now||now-identity.authTime>maxAge||!process.env.AUTH_STEP_UP_ACR||identity.acr!==process.env.AUTH_STEP_UP_ACR||!identity.amr?.includes("mfa"))throw Object.assign(new Error("Recent CSV staging MFA required"),{status:403});
   authTime=identity.authTime;
  }
  const action="source_stage:"+(csv?"csv":"json")+":"+createHash("sha256").update(body).digest("hex");
  const {rows:[ctx]}=await client.query("SELECT current_setting('app.tenant_nonce',true) AS nonce");
  const evidence=["profitpilot-privacy-step-up-v1",membership.tenantId.toLowerCase(),membership.userId.toLowerCase(),batchId.toLowerCase(),action,String(authTime),ctx.nonce].join("\n");
  const proof=createHmac("sha256",Buffer.from(process.env.TENANT_CONTEXT_HMAC_SECRET,"hex")).update(evidence).digest("hex");
  const {rows:[out]}=await client.query("SELECT private.stage_verified_source_rows($1,$2,$3,$4,$5) AS result",[membership.tenantId,batchId,body,authTime,proof]);
  return out.result;
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
