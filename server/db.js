import pg from "pg";
import {createHmac,createHash,randomBytes} from "node:crypto";
import {databaseSslConfig} from "./db-config.js";
import {verifyDatabaseReadiness} from "./database-readiness.js";
import {createWorkBudget} from "./request-budget.js";
const boundedDbWork=createWorkBudget(16);
const {Pool}=pg;
const ssl=databaseSslConfig();
export const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl,max:10,idleTimeoutMillis:30000,connectionTimeoutMillis:5000,statement_timeout:3000});
pool.on("error",()=>process.stderr.write(JSON.stringify({event:"idle_database_connection_error"})+"\n"));
export function sessionDigest(sessionId){
 if(typeof sessionId!=="string"||sessionId.length<1||sessionId.length>255||/[\p{C}]/u.test(sessionId))throw new Error("Invalid session identity");
 return createHash("sha256").update(sessionId,"utf8").digest("hex");
}
export async function checkIdentitySession(identity,client=pool){
 if(client===pool)return boundedDbWork(async()=>{const c=await pool.connect();try{return await checkIdentitySession(identity,c);}finally{c.release();}});
 if(!identity||typeof identity.subject!=="string"||!identity.subject||identity.subject.length>255||/[\p{C}]/u.test(identity.subject)||
 !Number.isSafeInteger(identity.authTime)||identity.authTime<=0||!Number.isSafeInteger(identity.issuedAt)||identity.authTime>identity.issuedAt+5)return false;
 let digest;try{digest=sessionDigest(identity.sessionId);}catch{return false;}
 const secret=process.env.TENANT_CONTEXT_HMAC_SECRET||"",keyId=process.env.TENANT_CONTEXT_HMAC_KEY_ID||"primary";
 if(secret.length%2!==0||!/^[a-f0-9]{64,}$/i.test(secret))throw new Error("Session signing configuration missing");
 const expires=String(Math.floor(Date.now()/1000)+30),nonce=randomBytes(16).toString("hex");
 const args=[identity.subject,String(identity.authTime),String(identity.issuedAt),digest,expires,nonce,keyId];
 const sig=createHmac("sha256",Buffer.from(secret,"hex")).update(["profitpilot-session-v1",...args].join("\n")).digest("hex");
 return (await client.query("SELECT private.session_authorized($1,$2,$3,$4,$5,$6,$7,$8) AS allowed",[...args,sig])).rows[0]?.allowed===true;
}
export async function withTenant(tenantId,subject,fn,identity){
 return boundedDbWork(()=>tenantTransaction(tenantId,subject,fn,identity));
}
async function tenantTransaction(tenantId,subject,fn,identity){
 tenantId=tenantId.toLowerCase();
 if(identity&&identity.subject!==subject)throw Object.assign(new Error("Session identity mismatch"),{status:403});
 if(typeof subject!=="string"||!subject)throw new Error("Verified identity subject is required for tenant context");
 const secret=process.env.TENANT_CONTEXT_HMAC_SECRET||"";
 const keyId=process.env.TENANT_CONTEXT_HMAC_KEY_ID||"primary";
 if(secret.length%2!==0||!/^[a-f0-9]{64,}$/i.test(secret))throw new Error("Tenant context signing secret must be at least 32 bytes of hexadecimal data");
 const expires=String(Math.floor(Date.now()/1000)+30);
 const nonce=randomBytes(16).toString("hex");
 const payload=[tenantId,subject,expires,nonce,keyId].join("\n");
 const signature=createHmac("sha256",Buffer.from(secret,"hex")).update(payload).digest("hex");
 const client=await pool.connect();
 let discarded=false;
 try{
  await client.query("BEGIN");
  // Bound query execution and idle tenant transactions to limit lock exhaustion.
  // SET LOCAL is scoped to this transaction and cannot leak into pooled sessions.
  await client.query("SET LOCAL statement_timeout = '3s'");
  await client.query("SET LOCAL idle_in_transaction_session_timeout = '5s'");
  await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[tenantId,subject,expires,nonce,keyId,signature]);
  if(identity&&!(await checkIdentitySession(identity,client)))throw Object.assign(new Error("Session revoked or unavailable"),{status:403});
  const result=await fn(client);
  await client.query("COMMIT");
  return result;
 }catch(error){
  try{await client.query("ROLLBACK");}
  catch(rollbackError){
   // Never reuse a connection whose tenant transaction could not be rolled back.
   discarded=true;
   client.release(rollbackError);
   throw new AggregateError([error,rollbackError],"Tenant transaction and rollback both failed");
  }
  throw error;
 }
 finally{if(!discarded)client.release();}
}
export async function health(){
 return boundedDbWork(async()=>{
  const client=await pool.connect();
  try{return await verifyDatabaseReadiness(client);}
  finally{client.release();}
 });
}
