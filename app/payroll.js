import {createPayrollClient,PayrollRequestError} from "./payroll-client.js";
const $=id=>document.getElementById(id);
const value=id=>$(id).value.trim();
const PAGE=50;
let offset=0,totalRows=0,busy=false,loaded=null,queue=null,invoiceQueue=null;
const client=createPayrollClient({getAccessToken:async()=>{const token=value("token");$("token").value="";return token;}});
const scope=()=>[value("tenant"),value("pool"),value("allocation")].join("|");
function invalidate(){loaded=null;$("ack").checked=false;$("detail").textContent="";$("confirmButton").disabled=true;}
function clearQueue(){queue=null;offset=0;totalRows=0;$("rows").replaceChildren();$("summary").textContent="";$("previous").disabled=true;$("next").disabled=true;}
function status(message){$("status").textContent=message;}
function sync(){for(const b of document.querySelectorAll("button"))b.disabled=busy;
 $("previous").disabled=busy||!queue||offset===0;$("next").disabled=busy||!queue||offset+PAGE>=totalRows;
 $("confirmButton").disabled=busy||loaded!==scope()||!$("ack").checked;
 $("invoiceDecisionButton").disabled=busy||!selectedInvoice()||!$("invoiceAck").checked;
}
async function execute(action,write=false){
 if(busy)return;busy=true;for(const el of document.querySelectorAll("input,select,textarea"))el.disabled=true;sync();
 try{await action();}
 catch(e){status(e instanceof PayrollRequestError?e.message:e instanceof TypeError?"Check the required IDs, amounts and evidence fields.":"Request failed. Review current server state before taking further action.");if(write){invalidate();clearInvoices();}}
 finally{busy=false;for(const el of document.querySelectorAll("input,select,textarea"))el.disabled=false;sync();}
}
function showReview(r,requestedOffset){
 clearQueue();offset=requestedOffset;totalRows=r.summary.total;queue={tenant:value("tenant"),batch:value("batch")};
 $("summary").textContent=Object.entries(r.summary).map(([k,v])=>k+": "+v).join(" · ");
 for(const item of r.items){const tr=document.createElement("tr");for(const cell of [item.rowNumber,item.decision,item.reason??"—"]){const td=document.createElement("td");td.textContent=String(cell);tr.append(td);}$("rows").append(tr);}
 status("Review queue loaded. Structural validation is not approval.");
}
function review(page){return execute(async()=>{clearQueue();const r=await client.review(value("tenant"),value("batch"),{offset:page,limit:PAGE});showReview(r,page);});}
$("review").addEventListener("click",()=>review(0));
$("previous").addEventListener("click",()=>review(Math.max(0,offset-PAGE)));
$("next").addEventListener("click",()=>review(offset+PAGE));
for(const key of ["tenant","batch"]){$(key).addEventListener("input",()=>{clearQueue();invalidate();$("poolResult").textContent="";if(key==="tenant"){$("pool").value="";$("allocation").value="";}});}
for(const key of ["pool","allocation"])$(key).addEventListener("input",invalidate);
$("ack").addEventListener("change",sync);
function form(id,action){$(id).addEventListener("submit",e=>{e.preventDefault();execute(action,true);});}
form("decision",async()=>{const row=Number(value("row"));const choice=value("choice");await client.decide(value("tenant"),value("batch"),row,{decision:choice,reason:value("decisionReason")});clearQueue();$("decision").reset();status("Review decision recorded. Load the queue again using a new token.");});
form("reconcile",async()=>{const r=await client.reconcile(value("tenant"),value("batch"),{declaredTotal:value("total"),sourceReference:value("source"),reason:value("reconcileReason")});$("pool").value=r.id;$("allocation").value="";invalidate();$("poolResult").textContent="Source-declared AUD "+r.totalAmount+" · externally verified: no";$("reconcile").reset();status("Source reconciled. Pool ID populated.");});
function addLine(){if($("lines").children.length>=100)return;const box=document.createElement("fieldset");
 const legend=document.createElement("legend");legend.textContent="Allocation line";box.append(legend);
 const fields=[["bucketType","Cost bucket","select"],["siteId","Site ID (site costs only)","input"],["amount","Amount (AUD)","input"],["sourceReference","Synthetic evidence reference","input"]];
 for(const [key,label,tag] of fields){const l=document.createElement("label");l.textContent=label;const input=document.createElement(tag);input.dataset.field=key;input.autocomplete="off";if(tag==="select"){for(const v of ["direct","approved_allocated","non_site","excluded"]){const opt=document.createElement("option");opt.value=v;opt.textContent=v.replaceAll("_"," ");input.append(opt);}}else if(key==="amount"){input.inputMode="decimal";input.required=true;}else if(key==="sourceReference"){input.maxLength=120;input.required=true;}l.append(input);box.append(l);}
 const rm=document.createElement("button");rm.type="button";rm.textContent="Remove line";rm.addEventListener("click",()=>{if(!busy&&$("lines").children.length>1)box.remove();});box.append(rm);$("lines").append(box);
}
$("add").addEventListener("click",addLine);addLine();
form("draft",async()=>{const lines=[...$("lines").children].map(box=>Object.fromEntries([...box.querySelectorAll("[data-field]")].map(el=>[el.dataset.field,el.value.trim()||null])));const r=await client.draft(value("tenant"),value("pool"),{lines,reason:value("draftReason")});$("allocation").value=r.id;invalidate();$("detail").textContent="Draft saved. Unallocated AUD "+r.unallocated+". Load details before approval.";status("Draft saved; no costs confirmed.");});
$("inspect").addEventListener("click",()=>execute(async()=>{invalidate();const target=scope();const r=await client.readAllocation(value("tenant"),value("pool"),value("allocation"));const a=r.allocation;if(a.id!==value("allocation")||target!==scope())throw new TypeError("Mismatched allocation");
 const rows=r.lines.map(l=>[l.bucketType,l.siteId??"No site","AUD "+l.amount].join(" | "));
 $("detail").textContent=["Status: "+a.status,"Source-declared total: AUD "+a.total_amount,"Direct: AUD "+a.direct_amount,"Approved allocated: AUD "+a.allocated_amount,"Non-site: AUD "+a.non_site_amount,"Excluded: AUD "+a.excluded_amount,"Unallocated: AUD "+a.residual_amount,"External verification: no",...rows].join("\n");
 if(a.status==="review")loaded=target;status("Allocation loaded. A different authorised approver must confirm.");
}));
form("confirm",async()=>{if(loaded!==scope()||!$("ack").checked)throw new TypeError("Read and acknowledge the specific allocation first");const r=await client.confirm(value("tenant"),value("pool"),value("allocation"),{reason:value("confirmReason"),acknowledged:true});invalidate();$("confirm").reset();status("Server returned "+r.status+". Reload allocation to verify current state.");});
$("clear").addEventListener("click",()=>{for(const el of document.querySelectorAll("input,textarea")){if(el.type==="checkbox")el.checked=false;else el.value="";}for(const f of document.querySelectorAll("form"))f.reset();$("lines").replaceChildren();addLine();clearQueue();invalidate();$("poolResult").textContent="";status("Workspace cleared. Provider session revocation is separate.");sync();});

form("expenseConfirm",async()=>{await client.confirmDeliveryExpense(value("tenant"),value("expenseMatch"),{reason:value("expenseReason"),costCategory:value("expenseCategory"),payrollOverlapReviewed:$("expensePayroll").checked,duplicateExpenseReviewed:$("expenseDuplicate").checked});$("expenseConfirm").reset();status("Expense match confirmed by server. Create a new report to include it.");});
$("tenant").addEventListener("input",()=>{$("expenseConfirm").reset();});
function invoiceScope(){return [value("tenant"),value("invoiceBatch")].join("|");}
function selectedInvoice(){
 if(!invoiceQueue||invoiceQueue.scope!==invoiceScope())return null;
 const item=invoiceQueue.items.find(i=>i.matchId===value("invoiceCandidate"));
 return item&&["candidate","held"].includes(item.decision)?item:null;
}
function clearInvoices(){
 invoiceQueue=null;$("invoiceCandidate").replaceChildren(new Option("Load candidates first",""));
 $("invoiceEvidence").textContent="";$("invoiceDecide").reset();sync();
}
function showInvoice(){
 $("invoiceDecide").reset();
 const item=invoiceQueue?.items.find(i=>i.matchId===value("invoiceCandidate"));
 $("invoiceEvidence").textContent=item?JSON.stringify(item,null,2):"";sync();
}
for(const key of ["tenant","invoiceBatch"]){
 $(key).addEventListener("input",()=>{clearInvoices();$("invoiceStage").reset();$("invoicePrepare").reset();if(key==="tenant"){$("invoiceBatch").value="";$("invoiceCreate").reset();}});
}
$("clear").addEventListener("click",clearInvoices);
$("invoiceCandidate").addEventListener("change",showInvoice);
$("invoiceDecision").addEventListener("change",()=>{$("invoiceAck").checked=false;sync();});
$("invoiceAck").addEventListener("change",sync);
function jsonArray(key){let parsed;try{parsed=JSON.parse(value(key));}catch{throw new TypeError("Invalid JSON");}if(!Array.isArray(parsed))throw new TypeError("JSON array required");return parsed;}
form("invoiceCreate",async()=>{clearInvoices();$("invoiceBatch").value="";const r=await client.createInvoiceBatch(value("tenant"),{sourceType:value("invoiceSource"),fileName:value("invoiceFile"),sha256:value("invoiceHash"),permissionReference:value("invoicePermission"),periodStart:value("invoiceStart"),periodEnd:value("invoiceEnd")});$("invoiceBatch").value=r.batch.id;$("invoiceCreate").reset();$("invoiceStage").reset();$("invoicePrepare").reset();status(r.idempotent?"Existing batch recovered. Verify source before further action.":"Invoice batch created; no financial records confirmed.");});
form("invoiceStage",async()=>{clearInvoices();const r=await client.stageInvoiceRows(value("tenant"),value("invoiceBatch"),{rows:jsonArray("invoiceRows")});$("invoiceStage").reset();status("Staged "+r.inserted+" rows; exact replays "+r.duplicates+". Separate source review required.");});
form("invoicePrepare",async()=>{clearInvoices();const r=await client.prepareInvoices(value("tenant"),value("invoiceBatch"),{manifest:jsonArray("invoiceManifest"),expectedRowCount:Number(value("invoiceCount")),reason:value("invoicePrepareReason"),sourceReviewed:$("invoiceSourceReviewed").checked});$("invoicePrepare").reset();status("Prepared "+r.rowCount+" lines. No matches confirmed. Load candidates with a separate reviewer token.");});
$("invoiceList").addEventListener("click",()=>execute(async()=>{clearInvoices();const s=invoiceScope();const r=await client.invoiceCandidates(value("tenant"),value("invoiceBatch"));if(s!==invoiceScope())throw new TypeError("Scope changed");invoiceQueue={scope:s,items:r.items};for(const i of r.items)$("invoiceCandidate").append(new Option(i.invoiceNumber+" / line "+i.lineNumber+" / "+i.direction+" / "+i.decision,i.matchId));status("Candidates loaded. Select the exact financial record to review.");}));
form("invoiceDecide",async()=>{const item=selectedInvoice();if(!item||!$("invoiceAck").checked)throw new TypeError("Select and review candidate");await client.decideInvoiceMatch(value("tenant"),item.matchId,{decision:value("invoiceDecision"),expectedDirection:item.direction,reason:value("invoiceDecisionReason"),acknowledged:true,costCategory:value("invoiceCategory"),payrollOverlapReviewed:$("invoiceOverlap").checked,duplicateExpenseReviewed:$("invoiceDuplicate").checked,siteOverheadReviewed:$("invoiceSiteOverhead").checked,...(value("invoiceCategory")==="shared_overhead"&&value("invoiceDecision")==="propose_shared_overhead"?{sharedOverheadShares:jsonArray("invoiceSharedShares"),sharedOverheadBasis:value("invoiceSharedBasis"),sharedOverheadReviewed:$("invoiceSharedReviewed").checked}:value("invoiceCategory")==="shared_overhead"&&value("invoiceDecision")==="confirmed"?{sharedOverheadProposalId:item.sharedOverheadProposal?.id,sharedOverheadReviewed:$("invoiceSharedReviewed").checked}:{})});clearInvoices();status("Action recorded. Reload candidates to inspect the saved proposal or verify the decision.");});
for(const key of ["tenant","reconcileSourceBatch"])$(key).addEventListener("input",()=>{$("reconcileSourceResult").textContent="";if(key==="tenant")$("reconcileSourceBatch").value="";});
$("clear").addEventListener("click",()=>{$("reconcileSourceResult").textContent="";});
$("reconcileSourceRead").addEventListener("click",()=>execute(async()=>{$("reconcileSourceResult").textContent="";const r=await client.reconcileStoredSource(value("tenant"),value("reconcileSourceBatch"));$("reconcileSourceResult").textContent=JSON.stringify(r,null,2);status("Source reconciliation checked; external completeness is not established.");}));
function clearReport(){$("reportResult").textContent="";}
for(const key of ["tenant","reportContract","reportSite","reportStart","reportEnd"]){$(key).addEventListener("input",()=>{$("reportId").value="";clearReport();});}
$("reportId").addEventListener("input",clearReport);
$("clear").addEventListener("click",clearReport);
function renderReport(r,withEvidence){
 const o=r.outputs;
 const version=r.formulaVersion??r.formula_version;
 if(!["0.2.0","0.3.0","0.4.0","0.5.0"].includes(version)||o?.reportType!=="partial_management_contribution"||o.completeness!=="incomplete"||o.marginPercent!==null)throw new TypeError("Unsupported report version");
 const lines=["PARTIAL MANAGEMENT CONTRIBUTION · INCOMPLETE","Report: "+r.id,"Formula: "+version,"Currency: AUD · "+o.taxBasis,
  "Confirmed customer revenue: AUD "+o.revenue,"Direct labour: AUD "+o.directLabour,"Approved allocated labour: AUD "+o.approvedAllocatedLabour,
  ...(["0.3.0","0.4.0","0.5.0"].includes(version)?["Included labour: AUD "+o.includedLabour,"Supplier expenses: AUD "+o.supplierCost,"Subcontractor expenses: AUD "+o.subcontractorCost,"Other direct delivery expenses: AUD "+o.otherDeliveryCost,"Confirmed expense lines: "+o.expenseLineCount,"Expense evidence: "+o.expenseEvidenceStatus,"Included delivery costs: AUD "+o.deliveryCost,"Included-cost margin only: "+(o.includedCostMarginPercent===null?"unavailable":o.includedCostMarginPercent+"%")]:["Included labour: AUD "+o.deliveryCost,"Historical labour-only report"]),"Partial contribution: AUD "+o.contribution,...(["0.4.0","0.5.0"].includes(version)?["Wholly attributable site overhead: AUD "+o.siteOverheadCost,...(version==="0.5.0"?["Approved shared overhead share: AUD "+o.sharedOverheadCost]:[]),"Result after included overhead: AUD "+o.includedOperatingResult,"Observed coverage (not completeness):",...["customer","supplier","payroll"].map(k=>k+": "+(o.coverage[k].percentage===null?"unavailable":o.coverage[k].percentage+"%"))]:[]),"Definitive margin: unavailable",
  "Confirmed invoice lines: "+o.invoiceLineCount,"Confirmed allocation lines: "+o.allocationLineCount,
  "Whole selected payroll pools (not additional contract costs):","Source-declared total: AUD "+o.poolContext.sourceDeclaredTotal,
  "Non-site: AUD "+o.poolContext.nonSite,"Excluded: AUD "+o.poolContext.excluded,"Unallocated: AUD "+o.poolContext.unallocated,
  ...o.limitations];
 if(withEvidence){lines.push("Saved scope: "+r.contract_id+" / "+r.site_id,"Period: "+r.period_start+" to "+r.period_end,"Evidence snapshot:",JSON.stringify(r.inputs,null,2));}
 $("reportResult").textContent=lines.join("\n");
}
form("reportCreate",async()=>{clearReport();$("reportId").value="";const r=await client.createContributionReport(value("tenant"),{contractId:value("reportContract"),siteId:value("reportSite"),periodStart:value("reportStart"),periodEnd:value("reportEnd")});$("reportId").value=r.id;renderReport(r,false);status("Partial report saved. Load it again to inspect the evidence snapshot.");});
$("reportRead").addEventListener("click",()=>execute(async()=>{clearReport();const r=await client.readContributionReport(value("tenant"),value("reportId"));if(r.id!==value("reportId"))throw new TypeError("Mismatched report");renderReport(r,true);status("Saved report and evidence loaded.");}));
sync();
