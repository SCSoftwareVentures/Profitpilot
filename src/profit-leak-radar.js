import {money,isIsoDate} from "./engine.js";

const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const KINDS=new Set(["unmatched_invoice","unapproved_variation","contract_rate_variance","duplicate_invoice_candidate","unallocated_labour"]);
const TAX_BASES=new Set(["gst_inclusive","gst_exclusive","no_gst"]);
const clean=(value,max)=>typeof value==="string"?value.trim().slice(0,max):"";

/**
 * Classify a potential profit leak without asserting that a loss occurred.
 * A caller-declared complete coverage flag is not independently verified here.
 */
export function assessLeakCandidate(observation={}){
  if(!observation||typeof observation!=="object"||Array.isArray(observation))throw new TypeError("A leak observation object is required.");
  const id=clean(observation.id,128),kind=clean(observation.kind,64);
  const currency=clean(observation.currency,3),taxBasis=clean(observation.taxBasis,32);
  const periodStart=observation.periodStart,periodEnd=observation.periodEnd;
  const amount=money(observation.amount);
  const summary=clean(observation.summary,500);
  const nextAction=clean(observation.nextAction,500);
  const evidenceRefs=Array.isArray(observation.evidenceRefs)
    ?observation.evidenceRefs.filter(x=>typeof x==="string"&&ID.test(x.trim())).map(x=>x.trim()).slice(0,50):[];
  const checks={
    identity:ID.test(id),
    kind:KINDS.has(kind),
    amount:amount!==null&&BigInt(amount.replace(".",""))>0n,
    currency:/^[A-Z]{3}$/.test(currency),
    taxBasis:TAX_BASES.has(taxBasis),
    period:isIsoDate(periodStart)&&isIsoDate(periodEnd)&&periodEnd>=periodStart,
    evidence:evidenceRefs.length>0,
    sourceCoverage:observation.sourceCoverage==="complete"
  };
  const ready=Object.values(checks).every(Boolean);
  const reasons=[];
  for(const [key,ok] of Object.entries(checks))if(!ok)reasons.push(key==="sourceCoverage"?"Source coverage is not declared complete; monetary exposure is withheld.":key+" is missing, invalid or unverified.");
  return {
    id:id||null,
    kind:KINDS.has(kind)?kind:null,
    status:ready?"candidate_for_human_review":"unverified",
    candidateAmount:ready?amount:null,
    currency:ready?currency:null,
    taxBasis:ready?taxBasis:null,
    period:ready?{start:periodStart,end:periodEnd}:null,
    evidenceRefs,
    summary,
    nextAction:nextAction||"Review the source evidence and reconcile against the approved contract and period.",
    verifiedLoss:null,
    recoveredValue:null,
    humanReviewRequired:true,
    checks,
    reasons,
    limitations:[
      "A candidate is not proof of a loss, fraud, overcharging, recoverable revenue or realised savings.",
      "The source-coverage declaration is supplied by the caller and is not independently verified by this function.",
      "No financial action, invoice change, customer communication or approval is performed."
    ]
  };
}
