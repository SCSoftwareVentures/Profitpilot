// Compare an independently declared batch inventory to the tenant's recorded period.
// This is not proof that every external transaction was supplied.
import {isIsoDate} from "./engine.js";
import {UUID} from "./canonical-invoices.js";
const TYPES=["customer_invoice","supplier_invoice","payroll"];
export function validatePeriodDeclaration(body){
 const {periodStart,periodEnd,expectedBatches,declaredEmptyTypes,inventoryReviewed}=body||{};
 if(inventoryReviewed!==true||!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart||
    !Array.isArray(expectedBatches)||expectedBatches.length>30||!Array.isArray(declaredEmptyTypes)||declaredEmptyTypes.length>3)
  return {error:"Explicit review, valid period and bounded source inventory required"};
 const ids=new Set(),types=new Set(),empty=new Set();
 const expected=[];
 for(const x of expectedBatches){
  if(!x||typeof x.batchId!=="string"||!UUID.test(x.batchId)||!TYPES.includes(x.sourceType)||ids.has(x.batchId.toLowerCase()))return {error:"Invalid or duplicate expected batch"};
  const id=x.batchId.toLowerCase();ids.add(id);types.add(x.sourceType);expected.push({batchId:id,sourceType:x.sourceType});
 }
 for(const t of declaredEmptyTypes){
  if(!TYPES.includes(t)||types.has(t)||empty.has(t))return {error:"Each empty source type must be unique and have no expected batches"};
  empty.add(t);
 }
 if(TYPES.some(t=>!types.has(t)&&!empty.has(t)))return {error:"Every source type requires an explicit inventory or empty declaration"};
 return {periodStart,periodEnd,expectedBatches:expected,declaredEmptyTypes:[...empty]};
}
export function reconcilePeriodInventory(declaration,recorded,summaries,legacySourceLineCount){
 const {periodStart,periodEnd,expectedBatches,declaredEmptyTypes}=declaration;
 const base={periodStart,periodEnd,scope:"tenant_recorded_batch_inventory",externallyVerified:false,completeSourceCoverage:false,declaredEmptyTypes,recordedBatchCount:recorded.length,legacySourceLineCount};
 if(recorded.length>30)return {...base,status:"recorded_batch_limit_exceeded",inventoryMatches:false,recordedBatchCountIsLowerBound:true};
 const expected=new Map(expectedBatches.map(x=>[x.batchId,x.sourceType])),found=new Map(recorded.map(x=>[x.id,x]));
 const missing=expectedBatches.filter(x=>!found.has(x.batchId)).map(x=>x.batchId);
 const unexpected=recorded.filter(x=>!expected.has(x.id)).map(x=>x.id);
 const wrongType=recorded.filter(x=>expected.has(x.id)&&expected.get(x.id)!==x.source_type).map(x=>x.id);
 const unaligned=recorded.filter(x=>!isIsoDate(x.start)||!isIsoDate(x.end)||x.start>x.end||x.start<periodStart||x.end>periodEnd).map(x=>x.id);
 const payroll=recorded.filter(x=>x.source_type==="payroll"&&isIsoDate(x.start)&&isIsoDate(x.end)).sort((a,b)=>a.start.localeCompare(b.start));
 const overlap=new Set();for(let i=0;i<payroll.length;i++)for(let j=i+1;j<payroll.length;j++)if(payroll[j].start<=payroll[i].end){overlap.add(payroll[i].id);overlap.add(payroll[j].id);}
 const byID=new Map(summaries.map(x=>[x.batchId,x]));
 const batches=recorded.map(x=>{const s=byID.get(x.id);return {batchId:x.id,sourceType:x.source_type,periodStart:x.start,periodEnd:x.end,batchStatus:x.status,sourceStatus:s?.sourceStatus??"not_checked",approvalStatus:s?.approvalStatus??"not_checked",rejectedRowsRequireReview:s?.rejectedRowsRequireReview??false,unallocatedPayroll:s?.allocation?.residual??null};});
 const outstanding=batches.filter(x=>x.sourceStatus!=="reconciled_declared_source"||
  (x.sourceType==="payroll"?(x.approvalStatus!=="allocation_reconciled"||x.rejectedRowsRequireReview||x.unallocatedPayroll!=="0.00"):x.approvalStatus!=="all_rows_confirmed")).map(x=>x.batchId);
 const inventoryMatches=!missing.length&&!unexpected.length&&!wrongType.length&&!unaligned.length;
 const issues=outstanding.length>0||overlap.size>0||legacySourceLineCount!==0;
 return {...base,inventoryMatches,status:!inventoryMatches?"inventory_mismatch":issues?"recorded_exceptions":!recorded.length?"no_recorded_sources":"declared_inventory_reconciled",
  missingExpectedBatchIds:missing,unexpectedRecordedBatchIds:unexpected,wrongSourceTypeBatchIds:wrongType,unalignedBatchIds:unaligned,overlappingPayrollBatchIds:[...overlap],outstandingBatchIds:outstanding,batches};
}
