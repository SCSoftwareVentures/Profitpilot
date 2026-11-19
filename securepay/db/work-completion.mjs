import {createHmac,createHash,randomUUID} from "node:crypto";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const ids=(...x)=>{if(!x.every(v=>typeof v==="string"&&uuid.test(v)))throw Error("Invalid completion scope");};
const expiry=()=>Math.floor(Date.now()/1000)+15;
export function makeWorkCompletionOwner({pool,actorId,key,scanner,disputeScanner}){
 ids(actorId);
 if(!pool?.query||!Buffer.isBuffer(key)||key.length!==32||typeof scanner?.attest!=="function")throw Error("Completion authority unavailable");
 const mac=args=>createHmac("sha256",key).update(args.join(":")).digest("hex");
 return Object.freeze({
  async participant({tenantId,milestoneId,op,body}){
   ids(tenantId,milestoneId);
   const invoke=async(action,payload)=>{const raw=JSON.stringify(payload),exp=expiry(),args=[tenantId,milestoneId,actorId,action,raw,exp],sig=mac(["sp-participant-v1",tenantId,milestoneId,actorId,action,createHash("sha256").update(raw).digest("hex"),exp]);return (await pool.query("SELECT securepay_private.owner_participant($1,$2,$3,$4,$5,$6,$7) AS result",[...args,sig])).rows[0]?.result;};
   const result=await participantRequest({invoke,scanner:disputeScanner,tenantId,milestoneId,actorId,op,body});
   return result?{ok:true,participant:result}:{ok:false};
  },
  async acknowledgeFundedCancellation({tenantId,planId,offerId,decisionId,payoutCents,refundCents}){
   const eventId=randomUUID();ids(tenantId,planId,offerId,eventId,decisionId);
   if(![payoutCents,refundCents].every(x=>Number.isSafeInteger(x)&&x>=0))throw Error("Invalid decision amount");
   const exp=expiry(),args=[tenantId,planId,offerId,eventId,decisionId,actorId,payoutCents,refundCents,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.owner_ack_negotiated($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) AS ok",[...args,mac(["sp-negotiated-ack-v1",...args])]);
   return {ok:r?.ok===true,moneyMoved:false};
  },
  async fundedCancellationStatus({tenantId,planId}){
   ids(tenantId,planId);const exp=expiry(),args=[tenantId,planId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.owner_funded_cancel_view($1,$2,$3,$4,$5) AS view",[...args,mac(["sp-funded-cancel-view-v1",...args])]);
   return r?.view?{ok:true,view:r.view}:{ok:false};
  },
  async offerFundedCancellation({offerId=randomUUID(),tenantId,planId,milestoneId,payoutCents,refundCents,reason,stateDigest}){
   ids(offerId,tenantId,planId,milestoneId);
   if(!Number.isSafeInteger(payoutCents)||payoutCents<0||!Number.isSafeInteger(refundCents)||refundCents<=0||typeof reason!=="string"||reason.trim().length<10||reason.length>2000||reason.includes("\0")||typeof stateDigest!=="string"||!/^[a-f0-9]{64}$/.test(stateDigest))throw Error("Invalid funded cancellation");
   const exp=expiry(),args=[offerId,tenantId,planId,milestoneId,actorId,payoutCents,refundCents,reason,stateDigest,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.offer_funded_cancel($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) AS offer",[...args,mac(["sp-funded-cancel-offer-v1",offerId,tenantId,planId,milestoneId,actorId,payoutCents,refundCents,Buffer.from(reason).toString("hex"),stateDigest,exp])]);
   return r?.offer?{ok:true,offer:r.offer}:{ok:false};
  },
  async withdrawFundedCancellation({tenantId,planId,offerId}){
   ids(tenantId,planId,offerId);const exp=expiry(),args=[tenantId,planId,offerId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.withdraw_funded_cancel($1,$2,$3,$4,$5,$6) AS ok",[...args,mac(["sp-funded-cancel-withdraw-v1",...args])]);
   return {ok:r?.ok===true,moneyMoved:false};
  },
  async contractStatus({tenantId,planId}){
   ids(tenantId,planId);const exp=expiry(),args=[tenantId,planId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.owner_contract_view($1,$2,$3,$4,$5) AS view",[...args,mac(["sp-contract-view-v1",...args])]);
   return r?.view?{ok:true,view:r.view}:{ok:false};
  },
  async offerChange({changeId=randomUUID(),tenantId,planId,kind,milestoneId=null,newAmountCents=null,newDescription=null,reason,stateDigest}){
   ids(changeId,tenantId,planId);if(typeof stateDigest!=="string"||!/^[a-f0-9]{64}$/.test(stateDigest)||!["variation","cancel_remaining"].includes(kind)||typeof reason!=="string"||reason.trim().length<10||reason.length>2000||reason.includes("\0"))throw Error("Invalid change");
   if(kind==="variation"){ids(milestoneId);if(!Number.isSafeInteger(newAmountCents)||newAmountCents<=0||typeof newDescription!=="string"||!newDescription.trim()||newDescription.length>500||newDescription.includes("\0"))throw Error("Invalid variation");}
   else if(milestoneId!==null||newAmountCents!==null||newDescription!==null)throw Error("Invalid cancellation");
   const exp=expiry(),args=[changeId,tenantId,planId,actorId,kind,milestoneId,newAmountCents,newDescription,reason,stateDigest,exp];
   const signature=mac(["sp-change-offer-v2",changeId,tenantId,planId,actorId,kind,milestoneId??"-",newAmountCents??"-",newDescription===null?"-":Buffer.from(newDescription).toString("hex"),Buffer.from(reason).toString("hex"),stateDigest,exp]);
   const {rows:[r]}=await pool.query("SELECT securepay_private.offer_contract_change($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) AS change",[...args,signature]);
   return r?.change?{ok:true,change:r.change}:{ok:false};
  },
  async withdrawChange({tenantId,planId,changeId}){
   ids(tenantId,planId,changeId);const exp=expiry(),args=[tenantId,planId,changeId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.withdraw_contract_change($1,$2,$3,$4,$5,$6) AS ok",[...args,mac(["sp-change-withdraw-v1",...args])]);
   return {ok:r?.ok===true,moneyMoved:false};
  },
  async publishQuote({quoteId=randomUUID(),tenantId,jobId,previousDigest=null,description,totalCents}){
   ids(quoteId,tenantId,jobId);
   if((previousDigest!==null&&(typeof previousDigest!=="string"||!/^[a-f0-9]{64}$/.test(previousDigest)))||typeof description!=="string"||!description.trim()||description.length>4000||description.includes("\0")||!Number.isSafeInteger(totalCents)||totalCents<=0)throw Error("Invalid quote");
   const exp=expiry(),args=[quoteId,tenantId,jobId,actorId,previousDigest,description,totalCents,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.publish_quote($1,$2,$3,$4,$5,$6,$7,$8,$9) AS quote",[...args,mac(["sp-quote-publish-v1",quoteId,tenantId,jobId,actorId,previousDigest??"-",Buffer.from(description).toString("hex"),totalCents,exp])]);
   return r?.quote?{ok:true,quote:r.quote}:{ok:false};
  },
  async quoteStatus({tenantId,jobId}){
   ids(tenantId,jobId);const exp=expiry(),args=[tenantId,jobId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.owner_quote_view($1,$2,$3,$4,$5) AS view",[...args,mac(["sp-quote-view-v1",...args])]);
   return r?.view?{ok:true,view:r.view}:{ok:false};
  },
  async offerPlan({planId=randomUUID(),tenantId,jobId,items,quoteDigest=null}){
   ids(planId,tenantId,jobId);
   if(!Array.isArray(items)||items.length<1||items.length>20||items.some(x=>!x||typeof x!=="object"||Object.keys(x).length!==4||!uuid.test(x.milestoneId)||!Number.isSafeInteger(x.amountCents)||x.amountCents<=0||typeof x.description!=="string"||!x.description.trim()||x.description.length>500||typeof x.final!=="boolean"))throw Error("Invalid milestone plan");
   const terms=JSON.stringify(items),exp=expiry();
   if(Buffer.byteLength(terms)>32768)throw Error("Plan exceeds size limit");
   if(quoteDigest!==null){
    if(typeof quoteDigest!=="string"||!/^[a-f0-9]{64}$/.test(quoteDigest))throw Error("Invalid quote digest");
    const args=[planId,tenantId,jobId,actorId,terms,quoteDigest,exp];
    const {rows:[r]}=await pool.query("SELECT securepay_private.offer_payment_plan_bound($1,$2,$3,$4,$5,$6,$7,$8) AS digest",[...args,mac(["sp-plan-offer-v2",planId,tenantId,jobId,actorId,quoteDigest,Buffer.from(terms).toString("hex"),exp])]);
    return r?.digest?{ok:true,planId,planDigest:r.digest}:{ok:false};
   }
   const args=[planId,tenantId,jobId,actorId,terms,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.offer_payment_plan($1,$2,$3,$4,$5,$6,$7) AS digest",[...args,mac(["sp-plan-offer-v1",planId,tenantId,jobId,actorId,Buffer.from(terms).toString("hex"),exp])]);
   return r?.digest?{ok:true,planId,planDigest:r.digest}:{ok:false};
  },
  async withdrawPlan({tenantId,planId}){
   ids(tenantId,planId);const exp=expiry(),args=[tenantId,planId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.withdraw_payment_plan($1,$2,$3,$4,$5) AS ok",[...args,mac(["sp-plan-withdraw-v1",...args])]);
   return {ok:r?.ok===true,moneyMoved:false};
  },
  async status({tenantId,milestoneId}){
   ids(tenantId,milestoneId);const exp=expiry(),args=[tenantId,milestoneId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.owner_work_status($1,$2,$3,$4,$5) AS result",[...args,mac(["sp-work-status-v1",...args])]);
   return r?.result?{ok:true,view:r.result}:{ok:false};
  },
  async start({completionId=randomUUID(),tenantId,milestoneId}){
   ids(completionId,tenantId,milestoneId);const exp=expiry(),args=[completionId,tenantId,milestoneId,actorId,exp];
   const {rows:[r]}=await pool.query("SELECT securepay_private.start_work_completion($1,$2,$3,$4,$5,$6) AS ok",[...args,mac(["sp-work-start-v1",...args])]);
   return r.ok?{ok:true,completionId}:{ok:false};
  },
  async upload({photoId=randomUUID(),completionId,tenantId,milestoneId,mediaType,content}){
   ids(photoId,completionId,tenantId,milestoneId);
   if(!Buffer.isBuffer(content)||content.length<8||content.length>2097152||!["image/png","image/jpeg"].includes(mediaType))throw Error("Invalid completion evidence");
   const original=Buffer.from(content),originalDigest=createHash("sha256").update(original).digest("hex");
   let proof;try{proof=await scanner.attest({photoId,tenantId,milestoneId,caseId:completionId,actorId,mediaType,content:Buffer.from(original)});}catch{return {ok:false};}
   if(!proof||proof.originalDigest!==originalDigest||proof.originalMediaType!==mediaType||!Buffer.isBuffer(proof.content)||proof.content.length>2097152)return {ok:false};
   const normalized=Buffer.from(proof.content),digest=createHash("sha256").update(normalized).digest("hex"),exp=expiry();
   if(proof.digest!==digest||(mediaType==="image/png"&&!normalized.equals(original)))return {ok:false};
   const scope=[photoId,completionId,tenantId,milestoneId,actorId,digest,mediaType,originalDigest];
   const {rows:[r]}=await pool.query("SELECT securepay_private.store_work_photo($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) AS ok",[...scope,normalized,exp,mac(["sp-work-photo-v1",...scope,exp]),proof.exp,proof.signature]);
   return r.ok?{ok:true,photoId,digest}:{ok:false};
  },
  async submit({completionId,tenantId,milestoneId,comments=""}){
   ids(completionId,tenantId,milestoneId);
   if(typeof comments!=="string"||comments.length>2000||comments.includes("\0"))throw Error("Invalid completion comments");
   const exp=expiry(),scope=[completionId,tenantId,milestoneId,actorId];
   const {rows:[r]}=await pool.query("SELECT securepay_private.submit_work_completion($1,$2,$3,$4,$5,$6,$7) AS ok",[...scope,comments,exp,mac(["sp-work-submit-v1",...scope,Buffer.from(comments).toString("hex"),exp])]);
   return {ok:r.ok===true,moneyMoved:false};
  }
 });
}
