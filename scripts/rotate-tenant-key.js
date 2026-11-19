import { timingSafeEqual } from "node:crypto";
import { pathToFileURL } from "node:url";
import pg from "pg";

const keyIdPattern=/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
const secretPattern=/^[a-fA-F0-9]{64}$/;
function checkId(id){if(typeof id!=="string"||!keyIdPattern.test(id))throw new Error("Invalid key ID");}
function checkSecret(secret){if(typeof secret!=="string"||!secretPattern.test(secret))throw new Error("Expected independent 32-byte hexadecimal signing key");}

export async function rotateTenantKey(pool,{action,keyId,replacementId,secret}){
 checkId(keyId);
 if(!["stage","revoke"].includes(action))throw new Error("Unknown key lifecycle action");
 checkSecret(secret);
 if(action==="revoke"){
  checkId(replacementId);
  if(replacementId===keyId)throw new Error("Replacement must be different from revoked key");
 }
 const material=Buffer.from(secret,"hex");
 const client=await pool.connect();
 let discard;
 try{
  await client.query("BEGIN");
  await client.query("SET LOCAL statement_timeout='10s'");
  await client.query("SELECT pg_advisory_xact_lock(647120631)");
  if(action==="stage"){
   const existing=await client.query("SELECT 1 FROM private.tenant_context_keys WHERE key_id=$1 OR secret=$2",[keyId,material]);
   if(existing.rowCount)throw new Error("Key ID or material has already been used");
   await client.query("INSERT INTO private.tenant_context_keys(key_id,secret,active) VALUES($1,$2,true)",[keyId,material]);
  }else{
   // Require proof that the operator possesses the staged replacement.
   const replacement=await client.query("SELECT secret FROM private.tenant_context_keys WHERE key_id=$1 AND active FOR UPDATE",[replacementId]);
   const actual=replacement.rows[0]?.secret;
   if(!actual||actual.length!==material.length||!timingSafeEqual(actual,material))throw new Error("Active replacement key could not be verified");
   const revoked=await client.query("UPDATE private.tenant_context_keys SET active=false WHERE key_id=$1 AND active RETURNING key_id",[keyId]);
   if(revoked.rowCount!==1)throw new Error("Active retiring key not found");
  }
  await client.query("COMMIT");
  return {action,keyId};
 }catch(error){
  try{await client.query("ROLLBACK");}catch(e){discard=e;}
  throw error;
 }finally{material.fill(0);client.release(discard);}
}

async function main(){
 const {ROTATION_ADMIN_DATABASE_URL:url,ROTATION_DATABASE_CA:ca,ROTATION_NEW_KEY_SECRET:secret}=process.env;
 if(!url||!ca)throw new Error("Verified TLS administrative connection required");
 const parsed=new URL(url);
 if(!["postgres:","postgresql:"].includes(parsed.protocol)||!parsed.hostname||!parsed.username||!parsed.password||parsed.search)throw new Error("Invalid administrative database connection");
 if(decodeURIComponent(parsed.username)==="profitpilot_app")throw new Error("Runtime credentials cannot rotate keys");
 const [action,keyId,replacementId]=process.argv.slice(2);
 if(action==="revoke"&&process.env.ROTATION_CONFIRM_REPLICAS_SWITCHED!=="yes")throw new Error("Verify all replicas switched and allow at least 60 seconds before revocation");
 const pool=new pg.Pool({connectionString:url,ssl:{ca,rejectUnauthorized:true},max:1,connectionTimeoutMillis:5000});
 try{const result=await rotateTenantKey(pool,{action,keyId,replacementId,secret});process.stdout.write(JSON.stringify({event:"tenant_key_lifecycle_complete",...result})+"\n");}
 finally{await pool.end();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(()=>{process.stderr.write("Tenant key operation failed; no secret or connection details logged.\n");process.exitCode=1;});
}
