// Independent hash-chain verification. Persist returned checkpoints outside the
// database to detect a privileged rewrite of both ledger and current head.
import {createHash} from "node:crypto";
const zero="0".repeat(64),hex=/^[a-f0-9]{64}$/;
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const integer=x=>typeof x==="string"&&/^(0|[1-9][0-9]*)$/.test(x);
export async function verifyAuditChain(pool,tenantId,{checkpoint=null,pageSize=200}={}){
 if(!pool?.query||!uuid.test(tenantId)||!Number.isInteger(pageSize)||pageSize<1||pageSize>1000)throw Error("Invalid audit scope");
 if(checkpoint&&(!integer(checkpoint.last_seq)||!hex.test(checkpoint.last_hash)||checkpoint.tenantId!==tenantId))throw Error("Invalid retained checkpoint");
 const {rows:[head]}=await pool.query("SELECT * FROM securepay_private.audit_checkpoint($1::uuid)",[tenantId]);
 if(!head||!integer(head.last_seq)||!hex.test(head.last_hash))return {ok:false,reason:"invalid_head"};
 const limit=BigInt(head.last_seq);
 const expected=checkpoint?BigInt(checkpoint.last_seq):null;
 if(expected!==null&&expected>limit)return {ok:false,reason:"truncated_history"};
 let n=0n,prior=zero;
 if(expected===0n&&checkpoint.last_hash!==zero)return {ok:false,reason:"checkpoint_mismatch"};
 while(n<limit){
  const {rows}=await pool.query("SELECT * FROM securepay_private.audit_page($1::uuid,$2::bigint,$3::bigint,$4::integer)",[tenantId,String(n),head.last_seq,pageSize]);
  if(!rows.length||rows.length>pageSize)return {ok:false,reason:"missing_entries"};
  for(const r of rows){
   if(!integer(r.seq)||BigInt(r.seq)!==n+1n||BigInt(r.seq)>limit||r.prev_hash!==prior||
     !/^[a-z_]{1,64}$/.test(r.source)||!["INSERT","UPDATE","DELETE","READ"].includes(r.operation)||!hex.test(r.row_digest)||!integer(r.occurred_us)||!hex.test(r.entry_hash))
    return {ok:false,reason:"invalid_entry"};
   const computed=createHash("sha256").update(["sp-audit-v1",tenantId,r.seq,prior,r.source,r.operation,r.row_digest,r.occurred_us].join("|")).digest("hex");
   if(computed!==r.entry_hash)return {ok:false,reason:"hash_mismatch"};
   n++;prior=computed;
   if(n===expected&&prior!==checkpoint.last_hash)return {ok:false,reason:"checkpoint_mismatch"};
  }
 }
 if(prior!==head.last_hash)return {ok:false,reason:"head_mismatch"};
 return {ok:true,checkpoint:{tenantId,last_seq:head.last_seq,last_hash:prior}};
}
