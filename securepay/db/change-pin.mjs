// Internal transaction-scoped helpers. subject MUST come from a verified
// identity-provider token, never a request body. Do not expose until signed
// tenant context, step-up grant issuance, and restricted RLS are integrated.
import {createPinCredential} from "../domain/pin-credential.mjs";
import {changePinSigned} from "./signed-commands.mjs";
const denied=()=>({ok:false,code:"AUTHORIZATION_DENIED"});
export async function resolvePayer(c,{tenantId,subject}) {
 if(!c?.query||typeof tenantId!=="string"||!tenantId||typeof subject!=="string"||!subject||subject.length>512)
   throw new Error("Verified payer identity required");
 const {rows}=await c.query("SELECT customer_id FROM securepay_payer_identities WHERE tenant_id=$1 AND auth_subject=$2 AND active=true FOR UPDATE",[tenantId,subject]);
 return rows.length===1?rows[0].customer_id:null;
}
// Must execute in a single transaction; caller must roll back on any exception.
// A pre-existing independently verified, single-use step-up grant is required.
// No code here issues grants, accepts admin overrides or performs payments.
export async function changePin(c,{tenantId,subject,purpose,grantRef,pin},pepper) {
 if(!["enroll","recover"].includes(purpose)||typeof grantRef!=="string"||!grantRef) return denied();
 const customerId=await resolvePayer(c,{tenantId,subject});
 if(!customerId)return denied();
 const {rows:[runtime]}=await c.query("SELECT current_user AS role");
 const restricted=runtime.role==="securepay_payer_runtime";
 const {rows:[existing]}=await c.query("SELECT customer_id FROM securepay_customer_pins WHERE tenant_id=$1 AND customer_id=$2"+(restricted?"":" FOR UPDATE"),[tenantId,customerId]);
 if((purpose==="enroll"&&existing)||(purpose==="recover"&&!existing))return denied();
 // Check before hashing; consume after hashing with actual wall clock.
 const grant=await c.query("SELECT grant_ref FROM securepay_pin_change_grants WHERE grant_ref=$1 AND tenant_id=$2 AND customer_id=$3 AND purpose=$4 AND consumed_at IS NULL AND expires_at>clock_timestamp()"+(restricted?"":" FOR UPDATE"),[grantRef,tenantId,customerId,purpose]);
 if(grant.rowCount!==1)return denied();
 const credential=await createPinCredential({tenantId,customerId,pin,pepper});
 if(restricted)return changePinSigned(c,{tenantId,customerId,grantRef,purpose,salt:credential.salt,pinHash:credential.pinHash},pepper);
 const used=await c.query("UPDATE securepay_pin_change_grants SET consumed_at=clock_timestamp() WHERE grant_ref=$1 AND consumed_at IS NULL AND expires_at>clock_timestamp() RETURNING grant_ref",[grantRef]);
 if(used.rowCount!==1)return denied();
 if(purpose==="enroll"){
   await c.query("INSERT INTO securepay_customer_pins(tenant_id,customer_id,salt,pin_hash) VALUES($1,$2,$3,$4)",[tenantId,customerId,credential.salt,credential.pinHash]);
 }else{
   await c.query("UPDATE securepay_customer_pins SET salt=$3,pin_hash=$4,failed_attempts=0,locked_until=NULL WHERE tenant_id=$1 AND customer_id=$2",[tenantId,customerId,credential.salt,credential.pinHash]);
   await c.query("DELETE FROM securepay_release_proofs WHERE tenant_id=$1 AND customer_id=$2 AND consumed_at IS NULL",[tenantId,customerId]);
 }
 // Revoke any other outstanding enrollment/recovery grants for this customer.
 await c.query("UPDATE securepay_pin_change_grants SET consumed_at=clock_timestamp() WHERE tenant_id=$1 AND customer_id=$2 AND consumed_at IS NULL",[tenantId,customerId]);
 return {ok:true};
}
