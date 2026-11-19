import pg from "pg";
import {createHmac,randomBytes} from "node:crypto";
const {Pool}=pg;
const ssl=process.env.DATABASE_SSL==="true"?{rejectUnauthorized:true}:false;
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
  await client.query(repeatableRead?"BEGIN ISOLATION LEVEL REPEATABLE READ":"BEGIN");
  await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[tenantId,subject,expires,nonce,keyId,signature]);
  const result=await fn(client);
  await client.query("COMMIT");
  return result;
 }catch(error){await client.query("ROLLBACK");throw error;}
 finally{client.release();}
}
export async function health(){const r=await pool.query("SELECT 1 AS ok");return r.rows[0].ok===1;}
