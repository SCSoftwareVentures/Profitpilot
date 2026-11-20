import pg from "pg";
import {createHmac,randomBytes} from "node:crypto";
import {validSubject} from "./auth.js";
import {databaseConfig,readSecret} from "./deployment.js";
const {Pool}=pg;
export const pool=new Pool({...databaseConfig(),max:10,idleTimeoutMillis:30000,connectionTimeoutMillis:5000});
pool.on("error",()=>{
 // pg already discarded the idle client. The next query can open a new connection.
 process.stderr.write('{"event":"database_idle_connection_lost"}\n');
});
export async function withTenant(tenantId,subject,fn,{repeatableRead=false}={}){
 if(!validSubject(subject))throw new Error("Verified identity subject is required for tenant context");
 const secret=readSecret("TENANT_CONTEXT_HMAC_SECRET");
 const keyId=process.env.TENANT_CONTEXT_HMAC_KEY_ID||"primary";
 if(secret.length%2!==0||!/^[a-f0-9]{64,}$/i.test(secret))throw new Error("Tenant context signing secret must be at least 32 bytes of hexadecimal data");
 const expires=String(Math.floor(Date.now()/1000)+30);
 const nonce=randomBytes(16).toString("hex");
 const payload=[tenantId,subject,expires,nonce,keyId].join("\n");
 const signature=createHmac("sha256",Buffer.from(secret,"hex")).update(payload).digest("hex");
 const client=await pool.connect();
 let discardError;
 const onConnectionError=error=>{discardError=error;};
 // The pool transfers responsibility for client error events while it is checked out.
 client.on("error",onConnectionError);
 try{
  await client.query(repeatableRead?"BEGIN ISOLATION LEVEL REPEATABLE READ":"BEGIN");
  await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[tenantId,subject,expires,nonce,keyId,signature]);
  const result=await fn(client);
  if(discardError)throw discardError;
  const commit=await client.query("COMMIT");
  if(commit.command!=="COMMIT")throw new Error("Tenant transaction did not commit");
  return result;
 }catch(error){
  // A failed COMMIT can leave the outcome unknown. Never replay the callback here.
  if(!discardError){
   try{await client.query("ROLLBACK");}
   catch(rollbackError){discardError=rollbackError;}
  }
  throw error;
 }finally{
  client.removeListener("error",onConnectionError);
  client.release(discardError);
 }
}
export async function health(){const r=await pool.query("SELECT 1 AS ok");return r.rows[0].ok===1;}
