// Domain-separated key. Provision only this derived key into the database,
// never the PIN pepper itself. Rotate both together before production.
import {createHmac,randomUUID} from "node:crypto";
export function deriveCommandKey(pepper){
 if(!Buffer.isBuffer(pepper)||pepper.length<32)throw new Error("SecurePay command authority unavailable");
 return createHmac("sha256",pepper).update("securepay-db-command-key-v1").digest();
}
function signed(pepper,parts){
 const expires=Math.floor(Date.now()/1000)+15;
 const key=deriveCommandKey(pepper);
 try{return {expires,sig:createHmac("sha256",key).update([...parts,expires].join(":")).digest("hex")};}
 finally{key.fill(0);}
}
export async function reserveSigned(c,{tenantId,customerId,milestoneId,amountCents,version,requestId,idempotencyKey,salt,pinHash},pepper){
 const proof=randomUUID();
 const args=[tenantId,customerId,milestoneId,String(amountCents),String(version),requestId,idempotencyKey,proof,salt,pinHash];
 const {expires,sig}=signed(pepper,["sp-release-v1",...args]);
 const {rows:[r]}=await c.query("SELECT securepay_private.reserve_signed($1::uuid,$2::uuid,$3::uuid,$4::bigint,$5::bigint,$6::uuid,$7::uuid,$8::uuid,$9::text,$10::text,$11::bigint,$12::text) AS id",[...args,expires,sig]);
 return r.id?{ok:true,releaseRequestId:r.id,milestoneId,amountCents:String(amountCents)}:{ok:false,code:"AUTHORIZATION_DENIED"};
}
export async function changePinSigned(c,{tenantId,customerId,grantRef,purpose,salt,pinHash},pepper){
 const args=[tenantId,customerId,grantRef,purpose,salt,pinHash];
 const {expires,sig}=signed(pepper,["sp-pin-change-v1",...args]);
 const {rows:[r]}=await c.query("SELECT securepay_private.change_pin_signed($1::uuid,$2::uuid,$3::uuid,$4::text,$5::text,$6::text,$7::bigint,$8::text) AS ok",[...args,expires,sig]);
 return r.ok===true?{ok:true}:{ok:false,code:"AUTHORIZATION_DENIED"};
}
