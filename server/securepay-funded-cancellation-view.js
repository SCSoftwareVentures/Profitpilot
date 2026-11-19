// Strict projection of bounded funded cancellation read models.
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const id=x=>typeof x==="string"&&uuid.test(x);
const hash=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const cents=x=>typeof x==="string"&&/^(0|[1-9][0-9]{0,15})$/.test(x)&&BigInt(x)<=9007199254740991n;
const text=(x,n)=>typeof x==="string"&&x.length<=n;
export function projectFundedCancellation(x,planId){
 if(!x||!id(planId)||x.planId!==planId||!Array.isArray(x.stages)||x.stages.length<1||x.stages.length>20||!Array.isArray(x.offers)||x.offers.length>20)throw Error("Invalid cancellation view");
 const stages=x.stages.map(m=>{
  if(!m||!id(m.milestoneId)||!cents(m.amountCents)||m.amountCents==="0"||!text(m.description,500)||!["planned","submitted","disputed","approved","release_pending","released","settled","cancelled"].includes(m.status)||!(m.stateDigest===null||hash(m.stateDigest)))throw Error("Invalid cancellation stage");
  return {milestoneId:m.milestoneId,amountCents:m.amountCents,description:m.description,status:m.status,stateDigest:m.stateDigest};
 });
 const ids=new Set(stages.map(m=>m.milestoneId));if(ids.size!==stages.length)throw Error("Duplicate stage");
 const offers=x.offers.map(o=>{
  if(!o||!id(o.offerId)||!ids.has(o.milestoneId)||!cents(o.payoutCents)||!cents(o.refundCents)||o.refundCents==="0"||!text(o.reason,2000)||!hash(o.offerDigest)||!["offered","accepted","withdrawn"].includes(o.status)||typeof o.current!=="boolean"||
    !(o.caseId===null||id(o.caseId))||![null,"open","decided","appealed","final","authorized","settled"].includes(o.caseStatus)||!(o.customerAcknowledged===null||typeof o.customerAcknowledged==="boolean")||!(o.ownerAcknowledged===null||typeof o.ownerAcknowledged==="boolean")||
    ![o.confirmedPayoutCents,o.confirmedRefundCents,o.remainingCents].every(cents)||![o.decisionPayoutCents,o.decisionRefundCents].every(y=>y===null||cents(y)))throw Error("Invalid cancellation offer");
  if((o.status==="accepted")!==(o.caseId!==null&&o.caseStatus!==null)||o.current&&o.status!=="offered")throw Error("Invalid cancellation lifecycle");
  const total=BigInt(o.payoutCents)+BigInt(o.refundCents);
  if(total>9007199254740991n||(o.current||o.status==="accepted")&&total!==BigInt(stages.find(m=>m.milestoneId===o.milestoneId).amountCents))throw Error("Invalid cancellation split");
  if(o.status==="accepted"&&BigInt(o.confirmedPayoutCents)+BigInt(o.confirmedRefundCents)+BigInt(o.remainingCents)!==total)throw Error("Unbalanced cancellation report");
  if(o.decision!==null&&(!o.decision||!id(o.decision.eventId)||!text(o.decision.reason,4000)||!hash(o.decision.evidenceDigest)||o.decisionPayoutCents===null||o.decisionRefundCents===null||BigInt(o.decisionPayoutCents)+BigInt(o.decisionRefundCents)!==total))throw Error("Invalid decision");
  return {offerId:o.offerId,milestoneId:o.milestoneId,payoutCents:o.payoutCents,refundCents:o.refundCents,reason:o.reason,offerDigest:o.offerDigest,status:o.status,current:o.current,caseId:o.caseId,caseStatus:o.caseStatus,decisionPayoutCents:o.decisionPayoutCents,decisionRefundCents:o.decisionRefundCents,customerAcknowledged:o.customerAcknowledged,ownerAcknowledged:o.ownerAcknowledged,decision:o.decision===null?null:{eventId:o.decision.eventId,reason:o.decision.reason,evidenceDigest:o.decision.evidenceDigest},confirmedPayoutCents:o.confirmedPayoutCents,confirmedRefundCents:o.confirmedRefundCents,remainingCents:o.remainingCents};
 });
 if(new Set(offers.map(o=>o.offerId)).size!==offers.length)throw Error("Duplicate offer");
 const settled=offers.filter(o=>o.status==="accepted"&&o.caseStatus==="settled");
 return {planId,stages,offers,confirmedCancellationRefundCents:String(settled.reduce((n,o)=>n+BigInt(o.confirmedRefundCents),0n)),confirmedCancellationPayoutCents:String(settled.reduce((n,o)=>n+BigInt(o.confirmedPayoutCents),0n))};
}
