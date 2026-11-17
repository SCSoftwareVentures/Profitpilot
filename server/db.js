import pg from "pg";
import {createHmac,randomBytes} from "node:crypto";
const {Pool}=pg;
const production=process.env.NODE_ENV==="production";
const databaseSslEnabled=process.env.DATABASE_SSL==="true";
if(production&&!databaseSslEnabled){
 throw new Error("DATABASE_SSL=true is required in production; refusing an unencrypted PostgreSQL connection");
}
const ssl=databaseSslEnabled?{rejectUnauthorized:true}:false;
export const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl,max:10,idleTimeoutMillis:30000,connectionTimeoutMillis:5000});
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

export async function registerAndCheckAuthSession({jti,subject,issuer,issuedAt,expiresAt}){
 const client=await pool.connect();
 try{
  await client.query("BEGIN");
  await client.query("SELECT private.register_bound_auth_session($1,$2,$3,to_timestamp($4),to_timestamp($5))",[jti,subject,issuer,issuedAt,expiresAt]);
  const result=await client.query("SELECT private.is_bound_auth_session_revoked($1,$2,$3) AS revoked",[jti,subject,issuer]);
  await client.query("COMMIT");
  return result.rows[0].revoked===true;
 }catch(error){await client.query("ROLLBACK");throw error;}
 finally{client.release();}
}
export async function listAuthSessions(subject){
 const result=await pool.query("SELECT jti,issued_at,expires_at,last_seen_at,revoked_at FROM private.list_auth_sessions($1)",[subject]);
 return result.rows;
}
export async function revokeAuthSession(jti,subject,reason="self_service_revocation"){
 const result=await pool.query("SELECT private.revoke_auth_session($1,$2,$3) AS revoked",[jti,subject,reason]);
 return result.rows[0].revoked===true;
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
