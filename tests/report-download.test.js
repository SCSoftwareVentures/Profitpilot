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
