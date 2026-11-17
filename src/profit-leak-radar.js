import {isIsoDate,money} from "./engine.js";

const COVERAGE=new Set(["complete","partial","unverified","missing"]);
const FORMULA_VERSION="profit-leak-radar-0.1.0";

function cents(value){
  const canonical=money(value);
  if(canonical===null)return null;
  const negative=canonical.startsWith("-");
  const unsigned=negative?canonical.slice(1):canonical;
  const [whole,fraction=""]=unsigned.split(".");
  const result=BigInt(whole)*100n+BigInt(fraction.padEnd(2,"0"));
  return negative?-result:result;
}
function decimal(centsValue){
  const negative=centsValue<0n;
  const absolute=negative?-centsValue:centsValue;
  return (negative?"-":"")+(absolute/100n).toString()+"."+(absolute%100n).toString().padStart(2,"0");
}
function textValue(value){return typeof value==="string"&&value.trim().length>0;}
function validBasis(basis){
  return Boolean(basis&&typeof basis==="object"&&/^[A-Z]{3}$/.test(basis.currency||"")&&textValue(basis.taxBasis)&&isIsoDate(basis.periodStart)&&isIsoDate(basis.periodEnd)&&basis.periodEnd>=basis.periodStart);
}
function sourceMatchesBasis(source,basis,amountKeys){
  if(!source||typeof source!=="object"||Array.isArray(source)||source.coverage!=="complete"||!textValue(source.evidenceRef)||source.currency!==basis.currency||source.taxBasis!==basis.taxBasis||source.periodStart!==basis.periodStart||source.periodEnd!==basis.periodEnd)return false;
  return amountKeys.every(key=>cents(source[key])!==null);
}
function unknownAlert(type,explanation,sourceRefs=[]){
  return {type,status:"unknown",amount:null,currency:null,direction:null,evidenceRefs:sourceRefs.filter(textValue),explanation,recommendedAction:"Obtain and reconcile the missing source evidence before quantifying this item."};
}
function candidateAlert(type,amount,basis,direction,evidenceRefs,explanation){
  return {type,status:"candidate",amount,currency:basis.currency,taxBasis:basis.taxBasis,periodStart:basis.periodStart,periodEnd:basis.periodEnd,direction,evidenceRefs:evidenceRefs.filter(textValue),explanation,recommendedAction:"Review the linked source records, approvals and period treatment. Do not book this candidate as a confirmed loss or saving."};
}

/**
 * Deterministic, evidence-gated exception detection.
 * Every monetary alert is a candidate only; this engine never confirms loss,
 * savings, fraud, overbilling, underbilling or recovered revenue.
 */
export function detectProfitLeaks(input){
  if(!input||typeof input!=="object"||Array.isArray(input)||!validBasis(input.reportingBasis))throw new TypeError("A valid explicit reporting basis is required");
  const basis=input.reportingBasis;
  const alerts=[];
  const contract=input.contract;
  const variations=input.variations;
  const invoices=input.invoices;
  if(!sourceMatchesBasis(contract,basis,["amount"])||!sourceMatchesBasis(variations,basis,["approvedAmount"])||!sourceMatchesBasis(invoices,basis,["amount"])){
    alerts.push(unknownAlert("contract_invoice_variance","Contract, approved-variation and invoice totals must all have complete matching currency, tax-basis, period and source evidence.",[contract?.evidenceRef,variations?.evidenceRef,invoices?.evidenceRef]));
  }else{
    const expected=cents(contract.amount)+cents(variations.approvedAmount);
    const actual=cents(invoices.amount);
    const variance=actual-expected;
    if(variance!==0n){
      const direction=variance<0n?"invoice_below_contract_plus_approved_variations":"invoice_above_contract_plus_approved_variations";
      alerts.push(candidateAlert("contract_invoice_variance",decimal(variance<0n?-variance:variance),basis,direction,[contract.evidenceRef,variations.evidenceRef,invoices.evidenceRef],"A difference exists between the contract amount plus explicitly approved variations and the invoice total. Billing schedule, credits, tax treatment and source coverage still require human review."));
    }
  }

  const payroll=input.payroll;
  if(!sourceMatchesBasis(payroll,basis,["poolAmount","allocatedAmount"])){
    alerts.push(unknownAlert("payroll_allocation_variance","Payroll pool and allocation totals are not both complete, evidenced and on the same reporting basis.",[payroll?.evidenceRef]));
  }else{
    const residual=cents(payroll.poolAmount)-cents(payroll.allocatedAmount);
    if(residual!==0n){
      alerts.push(candidateAlert("payroll_allocation_variance",decimal(residual<0n?-residual:residual),basis,residual>0n?"unallocated_pool":"over_allocated_pool",[payroll.evidenceRef],"The supplied payroll pool and allocation total differ. This is an allocation exception candidate, not proof of a site cost or employee underpayment."));
    }
  }

  if(invoices&&Array.isArray(invoices.rows)&&invoices.coverage==="complete"&&invoices.currency===basis.currency&&invoices.taxBasis===basis.taxBasis&&invoices.periodStart===basis.periodStart&&invoices.periodEnd===basis.periodEnd){
    for(const row of invoices.rows){
      if(!row||typeof row!=="object"||Array.isArray(row))continue;
      if(row.status==="unmatched"){
        const amount=cents(row.amount);
        alerts.push(amount===null||!textValue(row.evidenceRef)
          ?unknownAlert("unmatched_invoice_row","An unmatched invoice row lacks a valid exact amount or source evidence.",[row?.evidenceRef])
          :candidateAlert("unmatched_invoice_row",money(row.amount),basis,"unmatched",[row.evidenceRef],"An invoice row remains unmatched to a confirmed contract/site/service-period record."));
      }else if(row.status==="duplicate_candidate"){
        const amount=cents(row.amount);
        alerts.push(amount===null||!textValue(row.evidenceRef)
          ?unknownAlert("duplicate_invoice_candidate","A possible duplicate row lacks a valid exact amount or source evidence.",[row?.evidenceRef])
          :candidateAlert("duplicate_invoice_candidate",money(row.amount),basis,"possible_duplicate",[row.evidenceRef],"A source row is flagged as a duplicate candidate. Confirm invoice identity, credits and source lineage before any adjustment."));
      }
    }
  }else{
    alerts.push(unknownAlert("invoice_row_exceptions","Invoice row-level coverage and matching states are not complete on the selected reporting basis.",[invoices?.evidenceRef]));
  }

  const hasCandidate=alerts.some(alert=>alert.status==="candidate");
  const hasUnknown=alerts.some(alert=>alert.status==="unknown");
  return {
    formulaVersion:FORMULA_VERSION,
    reportingBasis:{...basis},
    status:hasCandidate?"review_required":hasUnknown?"incomplete_evidence":"no_candidate_alerts",
    alerts,
    candidateCount:alerts.filter(x=>x.status==="candidate").length,
    unknownCount:alerts.filter(x=>x.status==="unknown").length,
    interpretation:"Evidence-led candidates only. No alert is a confirmed loss, saving, fraud, overcharge, undercharge or recovered revenue. Incomplete or mismatched evidence remains unknown, never zero."
  };
}
