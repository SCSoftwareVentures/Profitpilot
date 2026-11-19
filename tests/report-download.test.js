import test from "node:test";
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {reportFiles,projectReportExport} from "../server/product-ui/report-download.js";
const run=randomUUID(),fixture={exportId:randomUUID(),calculationId:run,contractId:randomUUID(),siteId:randomUUID(),periodStart:"2026-11-01",periodEnd:"2026-11-14",currency:"AUD",completeness:"incomplete",revenue:"0.30",deliveryCost:"0.10",indicativeContribution:"0.20",contribution:null,marginPercent:null,sourceTrace:{status:"captured",format:"profitpilot-source-trace-v1",digest:"a".repeat(64),baselineId:randomUUID(),invoiceLineCount:2,reviewedInvoiceLineCount:2,allocationLineCount:1,capturedAt:"2026-11-19T08:00:00.123456+00:00",source_snapshot:"PRIVATE_FIXTURE"},privateNote:"PRIVATE_FIXTURE"};
test("minimized audited JSON and readable report preserve exact money and source reference",()=>{
 const {report,files}=reportFiles(fixture,run);assert.equal(files.length,2);
 assert.deepEqual(JSON.parse(files[0].content),report);assert.match(files[1].content,/Indicative contribution: AUD 0.20/);
 assert.match(files[1].content,/Definitive contribution: unavailable/);
 for(const f of files){assert.ok(!f.content.includes("PRIVATE_FIXTURE"));assert.ok(f.name.startsWith("profitpilot-management-"+run));}
 assert.equal(projectReportExport({...fixture,sourceTrace:{status:"legacy_unavailable"}},run).sourceTrace.status,"legacy_unavailable");
});
test("deny malformed, mismatched, fabricated definitive or non-reconciling reports",()=>{
 for(const patch of [{calculationId:randomUUID()},{currency:"USD"},{revenue:0.30},{indicativeContribution:"0.21"},{completeness:"complete"},{contribution:"0.20"},{marginPercent:"0.00"},{periodEnd:"2026-02-30"},{sourceTrace:null},{sourceTrace:{...fixture.sourceTrace,digest:"0".repeat(64)}},{sourceTrace:{...fixture.sourceTrace,reviewedInvoiceLineCount:3}}])
 assert.throws(()=>reportFiles({...fixture,...patch},run));
});

test("version two export separates reviewed direct supplier expenses and payroll",()=>{
 const v={...fixture,deliveryCost:"0.15",indicativeContribution:"0.15",sourceTrace:{...fixture.sourceTrace,format:"profitpilot-source-trace-v2",payrollCost:"0.10",supplierCost:"0.05",supplierLineCount:1,supplierExcludedLineCount:2,supplierPendingLineCount:3}};
 const {report,files}=reportFiles(v,run);assert.equal(report.sourceTrace.supplierCost,"0.05");assert.match(files[1].content,/Included direct supplier expenses: AUD 0[.]05/);assert.throws(()=>reportFiles({...v,sourceTrace:{...v.sourceTrace,supplierCost:"0.06"}},run));
});

test("v3 reconciles allocated overhead without charging site remainder",()=>{
 const v={...fixture,deliveryCost:"0.07",indicativeContribution:"0.23",sourceTrace:{...fixture.sourceTrace,format:"profitpilot-source-trace-v3",payrollCost:"0.03",supplierCost:"0.02",overheadCost:"0.02",sharedSourceCount:2,unallocatedSharedCost:"0.02",supplierLineCount:1,supplierExcludedLineCount:0,supplierPendingLineCount:1}};
 const {report,files}=reportFiles(v,run);assert.equal(report.sourceTrace.overheadCost,"0.02");assert.match(files[1].content,/Unallocated site remainder/);assert.throws(()=>reportFiles({...v,sourceTrace:{...v.sourceTrace,overheadCost:"0.03"}},run));
});

test("v4 reconciles business overhead and unallocated contextual remainder",()=>{
 const v={...fixture,deliveryCost:"0.08",indicativeContribution:"0.22",sourceTrace:{...fixture.sourceTrace,format:"profitpilot-source-trace-v4",payrollCost:"0.03",supplierCost:"0.02",overheadCost:"0.01",sharedSourceCount:2,unallocatedSharedCost:"0.02",supplierLineCount:1,supplierExcludedLineCount:0,supplierPendingLineCount:1,businessOverheadCost:"0.02",unallocatedBusinessOverhead:"0.03",businessOverheadSourceCount:1}};
 assert.equal(reportFiles(v,run).report.sourceTrace.businessOverheadCost,"0.02");assert.throws(()=>reportFiles({...v,sourceTrace:{...v.sourceTrace,businessOverheadCost:"0.03"}},run));
});
