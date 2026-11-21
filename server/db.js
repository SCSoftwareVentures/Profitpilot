import pg from "pg";
import {createHmac,randomBytes} from "node:crypto";
import {validSubject} from "./auth.js";
import {databaseConfig,readSecret} from "./deployment.js";
const {Pool}=pg;
export const pool=new Pool({...databaseConfig(),max:10,idleTimeoutMillis:30000,connectionTimeoutMillis:5000});

// Public handler stays bound to the application's single runtime pool.
export async function withTenant(tenantId,subject,fn,options={}){
 return withTenantUsingPool(pool,tenantId,subject,fn,options);
}

// Injection of a test-only pool enables real failure-mode tests without
// mutating the production singleton; handlers do not accept a pool from HTTP.
export async function withTenantUsingPool(dbPool,tenantId,subject,fn,
 {repeatableRead=false,env=process.env}={}){
 if(!validSubject(subject))throw new Error("Verified identity subject is required for tenant context");
 // RLS/HMAC input must be a canonical PostgreSQL UUID, never an unbounded
 // caller-controlled string (including delimiters in the signed payload).
 if(typeof tenantId!=="string"||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(tenantId))
  throw new Error("Validated tenant UUID is required for signed tenant context");
 const canonicalTenantId=tenantId.toLowerCase();
 if(!dbPool||typeof dbPool.connect!=="function"||typeof fn!=="function")
  throw new TypeError("Database pool and transaction callback required");
 const keyId=env.TENANT_CONTEXT_HMAC_KEY_ID??"primary";
 if(typeof keyId!=="string"||!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/.test(keyId))
  throw new Error("Valid bounded tenant signing key ID is required");
 const secret=readSecret("TENANT_CONTEXT_HMAC_SECRET",env);
 if(secret.length%2!==0||!/^[a-f0-9]{64,}$/i.test(secret))
  throw new Error("Tenant context signing secret must be at least 32 bytes of hexadecimal data");
 const expires=String(Math.floor(Date.now()/1000)+30);
 const nonce=randomBytes(16).toString("hex");
 const payload=[canonicalTenantId,subject,expires,nonce,keyId].join("\n");
 const signature=createHmac("sha256",Buffer.from(secret,"hex")).update(payload).digest("hex");
 const client=await dbPool.connect();
 let discardConnection=false,commitAttempted=false;
 try{
  await client.query(repeatableRead?"BEGIN ISOLATION LEVEL REPEATABLE READ":"BEGIN");
  await client.query("SET LOCAL statement_timeout = '15000ms'; SET LOCAL lock_timeout = '3000ms'; SET LOCAL idle_in_transaction_session_timeout = '20000ms'");
  await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[canonicalTenantId,subject,expires,nonce,keyId,signature]);
  const result=await fn(client);
  // A failed COMMIT can leave the transaction's outcome unknown (e.g.
  // connection loss after PostgreSQL committed). ROLLBACK success does not
  // establish whether COMMIT took effect, so never pool this client again.
  commitAttempted=true;
  await client.query("COMMIT");
  return result;
 }catch(error){
  if(commitAttempted)discardConnection=true;
  try{await client.query("ROLLBACK");}
  catch(rollbackError){
   // Unknown transaction/session state must never re-enter a pooled tenant.
   discardConnection=true;
   throw new AggregateError([error,rollbackError],
    "Tenant transaction failed and rollback failed; connection discarded");
  }
  throw error;
 }finally{
  // node-postgres pool.release(err) destroys/discards the connection.
  client.release(discardConnection?new Error("Unsafe tenant session after uncertain commit or failed rollback"):undefined);
 }
}
export async function health(){const r=await pool.query("SELECT 1 AS ok");return r.rows[0].ok===1;}
