/** SecurePay milestone domain draft. No payment provider calls or custody. */
export type MilestoneStatus="planned"|"submitted"|"disputed"|"approved"|"release_pending"|"released";
export interface Milestone {
 id:string; amountCents:number; description:string; final:boolean;
 status:MilestoneStatus; photos:string[]; comment?:string;
}
export interface Plan { totalCents:number; acceptedByCustomer:boolean; acceptedByOwner:boolean; milestones:Milestone[]; }
export type Action =
 | {type:"ACCEPT_PLAN";actor:"customer"|"owner"}
 | {type:"SUBMIT";actor:"owner";id:string;photos:string[];comment?:string}
 | {type:"DISPUTE";actor:"customer";id:string}
 | {type:"APPROVE";actor:"customer";id:string}
 | {type:"REQUEST_RELEASE";actor:"payment_service";id:string;verifiedAuthorizationRef:string}
 | {type:"CONFIRM_RELEASE";actor:"payment_service";id:string;providerTransactionRef:string};
const deny=():never=>{throw new Error("Milestone transition denied");};
export function createPlan(totalCents:number, items:{id:string;amountCents:number;description:string;final:boolean}[]):Plan {
 if(!Number.isSafeInteger(totalCents)||totalCents<=0||items.length===0||
    items.filter(x=>x.final).length!==1||new Set(items.map(x=>x.id)).size!==items.length||
    items.some(x=>!x.id.trim()||!x.description.trim()||!Number.isSafeInteger(x.amountCents)||x.amountCents<=0)||
    items.reduce((s,x)=>s+x.amountCents,0)!==totalCents) return deny();
 return {totalCents,acceptedByCustomer:false,acceptedByOwner:false,
   milestones:items.map(x=>({...x,status:"planned",photos:[]}))};
}
export function advance(plan:Readonly<Plan>,action:Action):Plan {
 if(action.type==="ACCEPT_PLAN") {
   if(plan.milestones.some(x=>x.status!=="planned")) return deny();
   return {...plan,[action.actor==="customer"?"acceptedByCustomer":"acceptedByOwner"]:true};
 }
 if(!plan.acceptedByCustomer||!plan.acceptedByOwner) return deny();
 const i=plan.milestones.findIndex(x=>x.id===action.id);
 if(i<0)return deny();
 const m=plan.milestones[i];
 let next:Milestone;
 switch(action.type) {
 case "SUBMIT":
   if(m.status!=="planned"||!action.photos.length||action.photos.some(x=>!x.trim()))return deny();
   // Final milestone must be submitted last; previous releases must be confirmed.
   if(m.final&&plan.milestones.some(x=>!x.final&&x.status!=="released"))return deny();
   next={...m,status:"submitted",photos:[...action.photos],comment:action.comment};break;
 case "DISPUTE":
   if(m.status!=="submitted")return deny();
   next={...m,status:"disputed"};break;
 case "APPROVE":
   if(m.status!=="submitted")return deny();
   next={...m,status:"approved"};break;
 case "REQUEST_RELEASE":
   // The caller must independently verify and consume a one-use, case-bound PIN
   // authorization before passing the reference; this function cannot verify it.
   if(m.status!=="approved"||!action.verifiedAuthorizationRef.trim())return deny();
   next={...m,status:"release_pending"};break;
 case "CONFIRM_RELEASE":
   if(m.status!=="release_pending"||!action.providerTransactionRef.trim())return deny();
   next={...m,status:"released"};break;
 default:return deny();
 }
 return {...plan,milestones:plan.milestones.map((x,j)=>i===j?next:x)};
}
