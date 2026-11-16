import pg from "pg";
const {Pool}=pg;
const ssl=process.env.DATABASE_SSL==="true"?{rejectUnauthorized:true}:false;
export const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl,max:10,idleTimeoutMillis:30000,connectionTimeoutMillis:5000});
export async function withTenant(tenantId,fn){
 const client=await pool.connect();
 try{
  await client.query("BEGIN");
  await client.query("SELECT set_config('app.tenant_id',$1,true)",[tenantId]);
  const result=await fn(client);
  await client.query("COMMIT");
  return result;
 }catch(error){await client.query("ROLLBACK");throw error;}
 finally{client.release();}
}
export async function health(){const r=await pool.query("SELECT 1 AS ok");return r.rows[0].ok===1;}
