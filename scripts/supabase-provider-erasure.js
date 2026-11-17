// Disabled-by-default, operator-only adapter. No browser or application route can invoke it.
import pg from "pg";
import {pathToFileURL} from "node:url";
import {restorePoolOptions} from "./privacy-restore-checkpoint.js";
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const issuerPattern=/^https:\/\/[a-z0-9]{20}\.supabase\.co\/auth\/v1$/;
export async function verifyAndEraseSupabaseIdentity({target,issuer,serviceRoleKey,enabled,fetchImpl=fetch}){
 if(enabled!==true||!issuerPattern.test(issuer||"")||target?.issuer!==issuer||!uuid.test(target?.subject||"")||!uuid.test(target?.grantId||"")||
 typeof serviceRoleKey!=="string"||serviceRoleKey.length<32)throw Error("Explicitly enabled matched provider authorization required");
 const url=issuer+"/admin/users/"+target.subject;
 const headers={apikey:serviceRoleKey,Authorization:"Bearer "+serviceRoleKey,Accept:"application/json"};
 async function request(method){
  return fetchImpl(url,{method,headers:method==="DELETE"?{...headers,"Content-Type":"application/json"}:headers,
  ...(method==="DELETE"?{body:JSON.stringify({should_soft_delete:false})}:{}),redirect:"error",signal:AbortSignal.timeout(8000)});
 }
 async function inspect(response){
  let body;try{body=await response.json();}catch{throw Error("Provider response not verifiable");}
  if(response.status===404&&(body?.code==="user_not_found"||body?.error_code==="user_not_found"))return "absent";
  if(response.status===200&&(body?.id===target.subject||body?.user?.id===target.subject))return "present";
  throw Error("Provider user state not verifiable");
 }
 if(await inspect(await request("GET"))==="absent")return {verifiedAbsent:true,alreadyAbsent:true};
 const deletion=await request("DELETE");
 if(!deletion.ok)throw Error("Provider deletion not confirmed");
 if(await inspect(await request("GET"))!=="absent")throw Error("Provider absence not confirmed");
 return {verifiedAbsent:true,alreadyAbsent:false};
}
async function main(){
 const grantId=process.argv[2],issuer=process.env.AUTH_ISSUER,serviceRoleKey=process.env.SUPABASE_SERVICE_ROLE_KEY;
 if(process.env.PRIVACY_PROVIDER_ERASURE_ENABLED!=="true"||!uuid.test(grantId||"")||!issuerPattern.test(issuer||"")||!serviceRoleKey)throw Error("Provider erasure is disabled or not configured");
 const pool=new pg.Pool(restorePoolOptions(process.env.PRIVACY_ADMIN_DATABASE_URL));
 let client;
 try{
  client=await pool.connect();
  await client.query("BEGIN");
  await client.query("SET LOCAL lock_timeout='5s'");
  await client.query("SET LOCAL idle_in_transaction_session_timeout='40s'");
  const target=(await client.query("SELECT private.provider_erasure_target($1,$2) AS target",[grantId,issuer])).rows[0].target;
  const result=await verifyAndEraseSupabaseIdentity({target,issuer,serviceRoleKey,enabled:true});
  if(!result.verifiedAbsent)throw Error("Provider absence not confirmed");
  const receipt=(await client.query("SELECT private.record_provider_erasure($1,$2) AS receipt",[grantId,issuer])).rows[0].receipt;
  await client.query("COMMIT");
  console.log(JSON.stringify(receipt));
 }catch{
  if(client)await client.query("ROLLBACK").catch(()=>{});
  throw Error("Provider erasure not fully recorded. Keep local account disabled and reconcile using authorized provider verification.");
 }finally{client?.release();await pool.end();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{console.error("Provider erasure failed closed or needs operator reconciliation.");process.exitCode=1;});
