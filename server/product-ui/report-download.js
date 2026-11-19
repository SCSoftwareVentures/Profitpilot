import {uuid,date,isDigest} from "./core.js";
// Only the reviewed, minimized export schema is written to a local file.
// Never copy arbitrary JSON properties, source rows, tokens, notes or HTML.
const money=x=>{if(typeof x!=="string"||!/^-?(0|[1-9][0-9]{0,27})\.[0-9]{2}$/.test(x))throw Error("Invalid exported monetary amount.");return x;};
const count=x=>{if(!Number.isInteger(x)||x<0||x>10000)throw Error("Invalid source receipt count.");return x;};
const requiredId=x=>{if(typeof x!=="string"||uuid(x)!==x)throw Error("Invalid exported identifier.");return x;};
export function projectReportExport(data,expectedRun){
 if(!data||typeof data!=="object"||Array.isArray(data)||data.calculationId!==expectedRun||data.currency!=="AUD"||data.completeness!=="incomplete"||data.contribution!==null||data.marginPercent!==null)throw Error("Export is not a supported incomplete AUD management report.");
 const periodStart=date(data.periodStart),periodEnd=date(data.periodEnd);if(periodEnd<periodStart)throw Error("Invalid exported period.");
 const raw=data.sourceTrace;
 let sourceTrace={status:"legacy_unavailable"};
 if(raw?.status==="captured"){
  if(!["profitpilot-source-trace-v1","profitpilot-source-trace-v2","profitpilot-source-trace-v3"].includes(raw.format)||!isDigest(raw.digest)||typeof raw.capturedAt!=="string"||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(raw.capturedAt)||!Number.isFinite(Date.parse(raw.capturedAt)))throw Error("Invalid source receipt.");
  const invoiceLineCount=count(raw.invoiceLineCount),reviewedInvoiceLineCount=count(raw.reviewedInvoiceLineCount),allocationLineCount=count(raw.allocationLineCount);
  if(!invoiceLineCount||!allocationLineCount||reviewedInvoiceLineCount>invoiceLineCount)throw Error("Invalid receipt coverage.");
  sourceTrace={status:"captured",format:raw.format,digest:raw.digest,baselineId:requiredId(raw.baselineId),invoiceLineCount,reviewedInvoiceLineCount,allocationLineCount,capturedAt:raw.capturedAt};
 }else if(raw?.status!=="legacy_unavailable")throw Error("Export receipt status unavailable.");
 const revenue=money(data.revenue),deliveryCost=money(data.deliveryCost),indicativeContribution=money(data.indicativeContribution);
 const minor=x=>BigInt(x.replace(".",""));
 if(["profitpilot-source-trace-v2","profitpilot-source-trace-v3"].includes(sourceTrace.format)){const payrollCost=money(raw.payrollCost),supplierCost=money(raw.supplierCost),overheadCost=sourceTrace.format==="profitpilot-source-trace-v3"?money(raw.overheadCost):"0.00";if(minor(payrollCost)<0n||minor(supplierCost)<0n||minor(overheadCost)<0n||minor(payrollCost)+minor(supplierCost)+minor(overheadCost)!==minor(deliveryCost))throw Error("Export cost breakdown does not reconcile.");Object.assign(sourceTrace,{payrollCost,supplierCost,supplierLineCount:count(raw.supplierLineCount),supplierExcludedLineCount:count(raw.supplierExcludedLineCount),supplierPendingLineCount:count(raw.supplierPendingLineCount)});}
 if(sourceTrace.format==="profitpilot-source-trace-v3"){const unallocatedSharedCost=money(raw.unallocatedSharedCost);if(minor(unallocatedSharedCost)<0n)throw Error("Invalid unallocated site remainder.");Object.assign(sourceTrace,{overheadCost:money(raw.overheadCost),unallocatedSharedCost,sharedSourceCount:count(raw.sharedSourceCount)});}
 if(minor(revenue)-minor(deliveryCost)!==minor(indicativeContribution))throw Error("Export totals do not reconcile.");
 return {exportId:requiredId(data.exportId),calculationId:requiredId(data.calculationId),contractId:requiredId(data.contractId),siteId:requiredId(data.siteId),periodStart,periodEnd,currency:"AUD",completeness:"incomplete",revenue,deliveryCost,indicativeContribution,contribution:null,marginPercent:null,sourceTrace,notice:"Management calculation only. Not audited or statutory profit. Other costs and exclusions are incomplete; definitive contribution and margin are unavailable."};
}
export function reportFiles(data,expectedRun){
 const report=projectReportExport(data,expectedRun),stem="profitpilot-management-"+report.calculationId;
 const lines=["PROFITPILOT — MANAGEMENT REPORT","SYNTHETIC CANDIDATE | INCOMPLETE", "", "Calculation: "+report.calculationId,"Audited export: "+report.exportId,"Contract: "+report.contractId,"Site: "+report.siteId,"Period: "+report.periodStart+" to "+report.periodEnd,"Currency: AUD","","Included invoice revenue: AUD "+report.revenue,(["profitpilot-source-trace-v2","profitpilot-source-trace-v3"].includes(report.sourceTrace.format)?"Included delivery costs: AUD ":"Included site payroll: AUD ")+report.deliveryCost,"Indicative contribution: AUD "+report.indicativeContribution,"Definitive contribution: unavailable","Margin: unavailable","",report.notice,""];
 const t=report.sourceTrace;
 if(t.status==="captured")lines.push("Source receipt SHA-256: "+t.digest,"Baseline: "+t.baselineId,"Reviewed invoice lines: "+t.reviewedInvoiceLineCount+" / "+t.invoiceLineCount,"Site allocation lines: "+t.allocationLineCount,"Captured: "+t.capturedAt);
 else lines.push("Historical source receipt unavailable.");
 if(["profitpilot-source-trace-v2","profitpilot-source-trace-v3"].includes(t.format))lines.push("Included payroll: AUD "+t.payrollCost,"Included direct supplier expenses: AUD "+t.supplierCost,"Supplier lines included/excluded/pending: "+t.supplierLineCount+"/"+t.supplierExcludedLineCount+"/"+t.supplierPendingLineCount);
 if(t.format==="profitpilot-source-trace-v3")lines.push("Allocated overhead: AUD "+t.overheadCost,"Reviewed shared sources: "+t.sharedSourceCount,"Unallocated site remainder (not charged; do not sum across contracts): AUD "+t.unallocatedSharedCost);
 return {report,files:[{name:stem+".json",type:"application/json",content:JSON.stringify(report,null,2)+"\n"},{name:stem+".txt",type:"text/plain;charset=utf-8",content:lines.join("\n")+"\n"}]};
}
