// Independent command key in the authority; legacy derivation remains for test fixtures only.
import {createHmac,randomUUID} from "node:crypto";
import {signEnvelope} from "./key-envelope.mjs";
export function deriveCommandKey(pepper){
 if(!Buffer.isBuffer(pepper)||pepper.length<32)throw new Error("SecurePay command authority unavailable");
 return createHmac("sha256",pepper).update("securepay-db-command-key-v1").digest();
}
function signed(pepper,parts,authority){
 const expires=Math.floor(Date.now()/1000)+15;
 const key=authority?.key??deriveCommandKey(pepper);
 try{return {expires,sig:signEnvelope(key,authority?.id??"primary",[...parts,expires].join(":"))};}
 finally{if(!authority)key.fill(0);}
}
export async function reserveSigned(c,{tenantId,customerId,milestoneId,amountCents,version,requestId,idempotencyKey,salt,pinHash},pepper,authority){
 const proof=randomUUID();
 const args=[tenantId,customerId,milestoneId,String(amountCents),String(version),requestId,idempotencyKey,proof,salt,pinHash];
 const {expires,sig}=signed(pepper,["sp-release-v1",...args],authority);
 const {rows:[r]}=await c.query("SELECT securepay_private.reserve_signed($1::uuid,$2::uuid,$3::uuid,$4::bigint,$5::bigint,$6::uuid,$7::uuid,$8::uuid,$9::text,$10::text,$11::bigint,$12::text) AS id",[...args,expires,sig]);
 return r.id?{ok:true,releaseRequestId:r.id,milestoneId,amountCents:String(amountCents)}:{ok:false,code:"AUTHORIZATION_DENIED"};
}
export async function changePinSigned(c,{tenantId,customerId,grantRef,purpose,salt,pinHash},pepper,authority){
 const args=[tenantId,customerId,grantRef,purpose,salt,pinHash];
 const {expires,sig}=signed(pepper,["sp-pin-change-v1",...args],authority);
 const {rows:[r]}=await c.query("SELECT securepay_private.change_pin_signed($1::uuid,$2::uuid,$3::uuid,$4::text,$5::text,$6::text,$7::bigint,$8::text) AS ok",[...args,expires,sig]);
 return r.ok===true?{ok:true}:{ok:false,code:"AUTHORIZATION_DENIED"};
}
