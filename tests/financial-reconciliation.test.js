import test from "node:test";
import assert from "node:assert/strict";
import {financialTotals} from "../src/financial-totals.js";
import {reconcileFinancialReport} from "../src/financial-reconciliation.js";
test("confirmed invoice and allocation aggregates reconcile exactly",()=>{
 const outputs=financialTotals("125.50","25.25");
 assert.deepEqual(reconcileFinancialReport(outputs,"125.50","25.25"),{
  status:"reconciled",revenueCents:"12550",deliveryCostCents:"2525",contributionCents:"10025",source:"confirmed_invoice_and_allocation_aggregates"
 });
});
test("reconciliation fails closed on mismatched invoice, payroll or contribution",()=>{
 const correct=financialTotals("125.50","25.25");
 for(const field of ["revenue","deliveryCost","contribution"]){
  assert.throws(()=>reconcileFinancialReport({...correct,[field]:correct[field]+0.01},"125.50","25.25"),/reconciliation failed/i);
 }
 assert.throws(()=>reconcileFinancialReport({...correct,contribution:100.251},"125.50","25.25"),/cent-precise/i);
 assert.throws(()=>reconcileFinancialReport(correct,"125.51","25.25"),/reconciliation failed/i);
});
