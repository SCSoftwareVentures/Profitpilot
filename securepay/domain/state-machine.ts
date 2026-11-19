/**
 * SecurePay v1: pure domain state machine, no live payment processing.
 * The caller MUST enforce authentication, database concurrency, idempotency,
 * immutable audit storage and provider-confirmed payment holds/releases.
 */
export type Severity = "minor" | "moderate" | "serious";
export type Status = "funded" | "submitted" | "disputed" | "rectification" |
  "review" | "approved" | "release_pending" | "released" | "closed";
export type Role = "owner" | "customer" | "reviewer" | "payment_service";
export type Event =
  | {type:"SUBMIT_WORK"; actor:"owner"; photos:string[]; comments?:string}
  | {type:"OPEN_DISPUTE"; actor:"customer"; reason:string; severity:Severity}
  | {type:"PROPOSE_REPAIR"; actor:"owner"; deadline:string}
  | {type:"ACCEPT_REPAIR"; actor:"customer"}
  | {type:"REFER_REVIEW"; actor:"customer"|"owner"}
  | {type:"SET_REPAIR_DEADLINE"; actor:"reviewer"; deadline:string; reasons:string}
  | {type:"SUBMIT_REPAIR"; actor:"owner"; photos:string[]; comments?:string}
  | {type:"APPROVE"; actor:"customer"}
  | {type:"PIN_VERIFIED"; actor:"customer"; verificationToken:string}
  | {type:"PROVIDER_RELEASE_CONFIRMED"; actor:"payment_service"; transactionId:string}
  | {type:"CLOSE_DISPUTE"; actor:"reviewer"; reasons:string; authorizedOutcomeRef:string};
export interface Case {
  status:Status; severity?:Severity; disputeReason?:string;
  photos?:string[]; comments?:string; repairDeadline?:string;
  repairProposed?:boolean; pinVerified?:boolean;
  releaseId?:string; decisionReasons?:string;
  authorizedOutcomeRef?:string;
}
const reject = ():never => {throw new Error("SecurePay transition denied");};
const nonempty=(s:string)=>s.trim().length>0;
export function transition(c:Readonly<Case>, e:Event):Case {
  switch(e.type) {
    case "SUBMIT_WORK":
      if(c.status!=="funded"||!e.photos.length) return reject();
      return {...c,status:"submitted",photos:[...e.photos],comments:e.comments};
    case "OPEN_DISPUTE":
      if(c.status!=="submitted"||!nonempty(e.reason)) return reject();
      return {...c,status:"disputed",severity:e.severity,disputeReason:e.reason};
    case "PROPOSE_REPAIR":
      if(c.status!=="disputed"||!nonempty(e.deadline)) return reject();
      return {...c,repairProposed:true,repairDeadline:e.deadline};
    case "ACCEPT_REPAIR":
      if(c.status!=="disputed"||!c.repairProposed) return reject();
      return {...c,status:"rectification"};
    case "REFER_REVIEW":
      if(c.status!=="disputed"&&c.status!=="rectification") return reject();
      return {...c,status:"review"};
    case "SET_REPAIR_DEADLINE":
      if(c.status!=="review"||!nonempty(e.deadline)||!nonempty(e.reasons)) return reject();
      return {...c,status:"rectification",repairDeadline:e.deadline};
    case "SUBMIT_REPAIR":
      if(c.status!=="rectification"||!e.photos.length) return reject();
      return {...c,status:"submitted",photos:[...e.photos],comments:e.comments,
        repairProposed:false};
    case "APPROVE":
      if(c.status!=="submitted") return reject();
      return {...c,status:"approved",pinVerified:false};
    case "PIN_VERIFIED":
      // Verification token must be validated server-side and bound to case,
      // amount, customer and expiry before calling this function.
      if(c.status!=="approved"||!nonempty(e.verificationToken)) return reject();
      return {...c,status:"release_pending",pinVerified:true};
    case "PROVIDER_RELEASE_CONFIRMED":
      if(c.status!=="release_pending"||!c.pinVerified||!nonempty(e.transactionId)) return reject();
      return {...c,status:"released",releaseId:e.transactionId};
    case "CLOSE_DISPUTE":
      if(c.status!=="review"||!nonempty(e.reasons)||!nonempty(e.authorizedOutcomeRef)) return reject();
      // Resolution is NOT a payment instruction. A separate authorised,
      // provider-controlled settlement workflow must handle monetary actions.
      return {...c,status:"closed",decisionReasons:e.reasons,
        authorizedOutcomeRef:e.authorizedOutcomeRef};
  }
}
export const INITIAL_CASE:Case={status:"funded"};
