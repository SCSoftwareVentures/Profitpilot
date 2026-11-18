import {exactAggregateCents} from "./financial-totals.js";

// Reconcile the report against the same confirmed source aggregates used to build it.
// Fail closed rather than persisting a report whose monetary totals disagree.
export function reconcileFinancialReport(outputs,revenueAggregate,costAggregate){
 const revenueCents=exactAggregateCents(revenueAggregate);
 const costCents=exactAggregateCents(costAggregate);
 const contributionCents=revenueCents-costCents;
 if(!Number.isSafeInteger(contributionCents))throw new RangeError("Unsafe reconciliation contribution");
 const amountCents=value=>{
  if(typeof value!=="number"||!Number.isFinite(value))throw new TypeError("Invalid report amount");
  const cents=Math.round(value*100);
  if(!Number.isSafeInteger(cents)||Math.abs(value*100-cents)>1e-7)throw new RangeError("Report amount is not cent-precise");
  return cents;
 };
 if(amountCents(outputs.revenue)!==revenueCents||
    amountCents(outputs.deliveryCost)!==costCents||
    amountCents(outputs.contribution)!==contributionCents)
  throw new Error("Financial reconciliation failed");
 return {status:"reconciled",revenueCents:String(revenueCents),deliveryCostCents:String(costCents),contributionCents:String(contributionCents),source:"confirmed_invoice_and_allocation_aggregates"};
}
