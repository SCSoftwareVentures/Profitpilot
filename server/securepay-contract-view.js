// Contract-view response projection. Do not forward arbitrary authority fields.
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const id=x=>typeof x==="string"&&uuid.test(x);
const cents=x=>typeof x==="string"&&/^(0|[1-9][0-9]{0,15})$/.test(x)&&BigInt(x)<=9007199254740991n;
const text=(x,n)=>typeof x==="string"&&x.length<=n;
export function projectContract(view,planId){
 const s=view?.state,changes=view?.changes;
 if(typeof view?.stateDigest!=="string"||!/^[a-f0-9]{64}$/.test(view.stateDigest)||!s||s.planId!==planId||!id(planId)||!cents(s.originalTotalCents)||!cents(s.effectiveTotalCents)||!Array.isArray(s.stages)||s.stages.length<1||s.stages.length>20||!Array.isArray(changes)||changes.length>20)throw Error("Invalid contract view");
 const stage=x=>{
  if(!x||!id(x.milestoneId)||!cents(x.amountCents)||x.amountCents==="0"||!text(x.description,500))throw Error("Invalid stage");
  return {milestoneId:x.milestoneId,amountCents:x.amountCents,description:x.description};
 };
 const stages=s.stages.map(x=>{
  const y=stage(x);
  if(!["planned","submitted","disputed","approved","release_pending","released","settled","cancelled"].includes(x.status)||!text(x.version,19)||!/^\d+$/.test(x.version)||typeof x.final!=="boolean"||typeof x.eligible!=="boolean"||typeof x.terminalVerified!=="boolean")throw Error("Invalid state");
  return {...y,status:x.status,version:x.version,final:x.final,eligible:x.eligible,terminalVerified:x.terminalVerified};
 });
 if(new Set(stages.map(x=>x.milestoneId)).size!==stages.length||stages.filter(x=>x.status!=="cancelled").reduce((n,x)=>n+BigInt(x.amountCents),0n)!==BigInt(s.effectiveTotalCents))throw Error("Invalid contract balance");
 const history=changes.map(x=>{
  if(!x||!id(x.changeId)||!["variation","cancel_remaining"].includes(x.kind)||!["offered","accepted","withdrawn"].includes(x.status)||!cents(x.oldTotalCents)||!cents(x.newTotalCents)||!text(x.reason,2000)||!text(x.changeDigest,64)||!/^[a-f0-9]{64}$/.test(x.changeDigest)||typeof x.current!=="boolean"||!Array.isArray(x.affectedStages)||x.affectedStages.length<1||x.affectedStages.length>20)throw Error("Invalid change");
  if(x.kind==="variation"?(!id(x.milestoneId)||!cents(x.newAmountCents)||x.newAmountCents==="0"||!text(x.newDescription,500)||x.affectedStages.length!==1||x.affectedStages[0].milestoneId!==x.milestoneId):(x.milestoneId!==null||x.newAmountCents!==null||x.newDescription!==null))throw Error("Invalid change terms");
  const affectedStages=x.affectedStages.map(stage);
  const expected=BigInt(x.oldTotalCents)-affectedStages.reduce((n,a)=>n+BigInt(a.amountCents),0n)+(x.kind==="variation"?BigInt(x.newAmountCents):0n);
  if(expected!==BigInt(x.newTotalCents)||new Set(affectedStages.map(a=>a.milestoneId)).size!==affectedStages.length)throw Error("Invalid change total");
  return {changeId:x.changeId,kind:x.kind,milestoneId:x.milestoneId,oldTotalCents:x.oldTotalCents,newTotalCents:x.newTotalCents,newAmountCents:x.newAmountCents,newDescription:x.newDescription,reason:x.reason,status:x.status,changeDigest:x.changeDigest,current:x.current,affectedStages};
 });
 return {stateDigest:view.stateDigest,state:{planId,originalTotalCents:s.originalTotalCents,effectiveTotalCents:s.effectiveTotalCents,stages},changes:history};
}
