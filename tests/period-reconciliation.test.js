import test from "node:test";
import assert from "node:assert/strict";
import {validatePeriodDeclaration,reconcilePeriodInventory} from "../src/period-reconciliation.js";
const id="11111111-1111-4111-8111-111111111111",other="22222222-2222-4222-8222-222222222222";
const body={periodStart:"2026-02-01",periodEnd:"2026-02-28",expectedBatches:[{batchId:id,sourceType:"payroll"}],declaredEmptyTypes:["customer_invoice","supplier_invoice"],inventoryReviewed:true};
const row={id,source_type:"payroll",status:"accepted",start:body.periodStart,end:body.periodEnd};
const summary={batchId:id,sourceStatus:"reconciled_declared_source",approvalStatus:"allocation_reconciled",allocation:{residual:"0.00"}};
test("inventory requires explicit classification of all sources and refuses ambiguous declarations",()=>{
 assert.equal(validatePeriodDeclaration(body).error,undefined);
 for(const patch of [{inventoryReviewed:false},{declaredEmptyTypes:["customer_invoice"]},{declaredEmptyTypes:["payroll","supplier_invoice","customer_invoice"]},{expectedBatches:[...body.expectedBatches,...body.expectedBatches]},{periodEnd:"2026-01-01"}])assert.ok(validatePeriodDeclaration({...body,...patch}).error);
});
test("recorded inventory reconciliation stays separate from external completeness",()=>{
 const d=validatePeriodDeclaration(body);let result=reconcilePeriodInventory(d,[row],[summary],0);
 assert.equal(result.status,"declared_inventory_reconciled");assert.equal(result.completeSourceCoverage,false);
 assert.equal(reconcilePeriodInventory(d,[row],[{...summary,allocation:{residual:"1.00"}}],0).status,"recorded_exceptions");
 assert.equal(reconcilePeriodInventory(d,[row],[summary],1).status,"recorded_exceptions");
 assert.equal(reconcilePeriodInventory(d,[],[],0).status,"inventory_mismatch");
 assert.equal(reconcilePeriodInventory(d,[{...row,start:"2026-01-31"}],[summary],0).status,"inventory_mismatch");
 result=reconcilePeriodInventory(d,[row,{...row,id:other}],[summary],0);assert.deepEqual(result.unexpectedRecordedBatchIds,[other]);assert.equal(result.overlappingPayrollBatchIds.length,2);
});
