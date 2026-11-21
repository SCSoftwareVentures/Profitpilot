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
 if(!dbPool||typeof dbPool.connect!=="function"||typeof fn!=="function")
  throw new TypeError("Database pool and transaction callback required");
 const secret=readSecret("TENANT_CONTEXT_HMAC_SECRET",env);
 const keyId=env.TENANT_CONTEXT_HMAC_KEY_ID||"primary";
 if(secret.length%2!==0||!/^[a-f0-9]{64,}$/i.test(secret))
  throw new Error("Tenant context signing secret must be at least 32 bytes of hexadecimal data");
 const expires=String(Math.floor(Date.now()/1000)+30);
 const nonce=randomBytes(16).toString("hex");
 const payload=[tenantId,subject,expires,nonce,keyId].join("\n");
 const signature=createHmac("sha256",Buffer.from(secret,"hex")).update(payload).digest("hex");
 const client=await dbPool.connect();
 let discardConnection=false;
 try{
  await client.query(repeatableRead?"BEGIN ISOLATION LEVEL REPEATABLE READ":"BEGIN");
  await client.query("SET LOCAL statement_timeout = '15000ms'; SET LOCAL lock_timeout = '3000ms'; SET LOCAL idle_in_transaction_session_timeout = '20000ms'");
  await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[tenantId,subject,expires,nonce,keyId,signature]);
  const result=await fn(client);
  await client.query("COMMIT");
  return result;
 }catch(error){
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
  client.release(discardConnection?new Error("Unsafe tenant session after failed rollback"):undefined);
 }
}
export async function health(){const r=await pool.query("SELECT 1 AS ok");return r.rows[0].ok===1;}
