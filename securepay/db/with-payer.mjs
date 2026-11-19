// Internal server adapter. Dedicated payer runtime only, never the staff pool.
// The subject must be supplied by verified auth middleware, not a request body.
import {randomBytes} from "node:crypto";
import {signEnvelope,validKeyId} from "./key-envelope.mjs";
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export async function withPayer(pool,{tenantId,subject,signingKey,contextKeyId="primary"},fn) {
 if(!pool?.connect||typeof tenantId!=="string"||!uuid.test(tenantId)||
    typeof subject!=="string"||!subject||subject.length>512||
    !Buffer.isBuffer(signingKey)||signingKey.length!==32||!validKeyId(contextKeyId)||typeof fn!=="function")
   throw new Error("Verified payer context unavailable");
 const c=await pool.connect();let begun=false,discard;
 try{
  await c.query("BEGIN");begun=true;
  const {rows:[r]}=await c.query("SELECT current_user AS role");
  if(r.role!=="securepay_payer_runtime")throw new Error("Incorrect payer runtime role");
  const expires=String(Math.floor(Date.now()/1000)+30);
  const nonce=randomBytes(16).toString("hex");
  const payload=["securepay-payer-v1",tenantId,Buffer.from(subject,"utf8").toString("hex"),expires,nonce].join(":");
  const signature=signEnvelope(signingKey,contextKeyId,payload);
  await c.query("SELECT set_config('sp.tenant',$1,true),set_config('sp.subject',$2,true),set_config('sp.expiry',$3,true),set_config('sp.nonce',$4,true),set_config('sp.signature',$5,true)",[tenantId,subject,expires,nonce,signature]);
  const verify=async()=>{const {rows:[p]}=await c.query("SELECT securepay_private.current_payer($1::uuid) AS payer",[tenantId]);if(!p.payer)throw new Error("Payer context denied");return p.payer;};
  const initial=await verify();
  const result=await fn(c);
  if(await verify()!==initial)throw new Error("Payer context changed");
  await c.query("COMMIT");begun=false;return result;
 }catch(e){
  if(begun)try{await c.query("ROLLBACK");}catch(r){discard=r;throw new AggregateError([e,r],"Payer transaction rollback failed");}
  throw e;
 }finally{c.release(discard);}
}
