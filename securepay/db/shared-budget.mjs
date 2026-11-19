import {createHmac} from "node:crypto";
// This key must be identical on all authority instances and distinct from other
// signing keys. No raw identity, bearer token or IP is stored.
export function makeSharedCustomerBudget({pool,key,issuer}){
 if(!pool?.query||!Buffer.isBuffer(key)||key.length!==32||typeof issuer!=="string"||!issuer)throw Error("Shared budget unavailable");
 return async identity=>{
  if(typeof identity?.subject!=="string"||!identity.subject||identity.subject.length>512)return false;
  const digest=createHmac("sha256",key).update(JSON.stringify([issuer,identity.subject])).digest("hex");
  const {rows:[r]}=await pool.query("SELECT securepay_private.take_customer_budget($1::text) AS allowed",[digest]);
  return r?.allowed===true;
 };
}
