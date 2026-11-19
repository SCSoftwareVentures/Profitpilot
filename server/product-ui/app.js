import {uuid,amount,date,range,cents,decimal,parseMinimizedRows,mappingLine,mappingKey,assignedSites,checksum,isDigest,tenantPath} from "./core.js";
const el=id=>document.getElementById(id),value=id=>el(id).value,uid=id=>uuid(value(id)),set=(id,v)=>{el(id).value=v??"";};
const kinds=["business","customer","site","contract","contract_site"];
const names={business:"Businesses",customer:"Customers",site:"Sites",contract:"Contracts",contract_site:"Site assignments"};
let records=Object.fromEntries(kinds.map(k=>[k,[]])),jobs=[],cursors={},mappings=[],currentJob=null,acceptedInvoice=null,session=null,busy=false,epoch=0,controller=null;
const required=(id,label)=>{const v=value(id).trim();if(!v)throw Error(label+" is required.");return v;};
const evidence=id=>{const v=value(id).trim();if(!isDigest(v))throw Error("Supply the exact nonzero SHA-256 evidence reference.");return v;};
const confirmed=id=>{if(!el(id).checked)throw Error("Explicit confirmation required.");el(id).checked=false;};
const status=(message,error=false)=>{el("status").textContent=message;el("status").classList.toggle("error",error);};
function show(id,data){el(id).textContent=JSON.stringify(data,null,2);}
function nameOf(id){for(const k of kinds){const r=records[k].find(x=>x.id===id);if(r)return r.label||r.id;}return id;}
function make(tag,text,css){const n=document.createElement(tag);if(text!==undefined)n.textContent=String(text);if(css)n.className=css;return n;}
function card(title,detail,buttonText,handler){const n=make("div",undefined,"item");n.append(make("strong",title),make("small",detail));if(handler){const b=make("button",buttonText);b.type="button";b.addEventListener("click",handler);n.append(b);}return n;}
function options(id,items,placeholder){const node=el(id),previous=node.value;node.replaceChildren(new Option(placeholder,""),...items.map(x=>new Option(x.label||x.id,x.id)));if(items.some(x=>x.id===previous))node.value=previous;}
function credentials(){const tenant=uid("tenant"),token=value("token").trim();if(!token||token.length>8192||/\s/.test(token))throw Error("Supply a current synthetic access token.");return {tenant,token};}
function reset(keepCredentials=false){
 epoch++;controller?.abort();controller=null;session=null;records=Object.fromEntries(kinds.map(k=>[k,[]]));jobs=[];cursors={};mappings=[];currentJob=null;acceptedInvoice=null;
 for(const n of document.querySelectorAll("input,textarea")){if(keepCredentials&&["tenant","token"].includes(n.id))continue;if(n.type==="checkbox")n.checked=false;else n.value="";}
 for(const n of document.querySelectorAll(".result,.stack,#metrics,#page-note"))n.replaceChildren();
 el("workspace").hidden=true;el("session-note").textContent="Not connected.";status("Session cleared. Verify a synthetic session.");
}
function switchTab(tab){for(const n of document.querySelectorAll("[data-panel]"))n.hidden=n.dataset.panel!==tab;for(const n of document.querySelectorAll("[data-tab]"))n.setAttribute("aria-selected",String(n.dataset.tab===tab));}
document.querySelectorAll("[data-tab]").forEach(n=>n.addEventListener("click",()=>switchTab(n.dataset.tab)));
for(const id of ["tenant","token"])el(id).addEventListener("input",()=>{if(session||busy)reset(true);});
window.addEventListener("pagehide",()=>reset());
window.addEventListener("pageshow",e=>{if(e.persisted)reset();});
async function request(path,body,ctx,signal){
 const credentialsNow=credentials();if(credentialsNow.tenant!==ctx.tenant)throw Error("Session changed.");
 let response;
 try{response=await fetch(path,{method:body===undefined?"GET":"POST",headers:{Authorization:"Bearer "+credentialsNow.token,...(body===undefined?{}:{"Content-Type":"application/json"})},credentials:"omit",cache:"no-store",redirect:"error",signal,body:body===undefined?undefined:JSON.stringify(body)});}
 catch(e){if(e.name==="AbortError")throw e;throw Error(body===undefined?"Unable to read. Check the connection.":"Result unknown. Read the exact record or order before retrying; do not replay blindly.");}
 let data;try{data=await response.json();}catch{throw Error("Response unavailable. Read the exact record before retrying.");}
 if(!response.ok){if(response.status===401||response.status===403)throw Error("Authority denied or session expired. Check tenant, role, MFA and current token.");if(response.status>=500)throw Error(body===undefined?"Service unavailable. Try reading later.":"Service unavailable; write result may be unknown. Reconcile exact record before retrying.");throw Error("HTTP "+response.status+": "+(typeof data?.error==="string"?data.error:"Request denied."));}
 return data;
}
async function read(path,body){if(!session)throw Error("Connect a workspace first.");const current=epoch;const data=await request(tenantPath(session.tenant,path),body,session,controller.signal);if(current!==epoch)throw Error("Session changed.");return data;}
function refreshOptions(){
 const contracts=records.contract;
 for(const id of ["baseline-contract","job-contract","report-contract"])options(id,contracts,"Choose contract");
 options("mapping-site",records.site,"Choose site");
 options("job-site",assignedSites(records,value("job-contract")),"Choose assigned site");
 options("report-site",assignedSites(records,value("report-contract")),"Choose assigned site");
 setRecordOptions();
}
function setRecordOptions(){
 const kind=value("record-kind"),parent=kind==="business"?[]:kind==="contract_site"?records.contract:records.business;
 options("record-parent",parent,kind==="business"?"Not applicable":"Choose parent");
 const p=value("record-parent"),contract=records.contract.find(x=>x.id===p);
 const related=kind==="contract"?records.customer.filter(x=>x.parentId===p):kind==="contract_site"?records.site.filter(x=>x.parentId===contract?.parentId):[];
 options("record-related",related,related.length?"Choose related record":"Not applicable");
}
el("record-kind").addEventListener("change",setRecordOptions);el("record-parent").addEventListener("change",setRecordOptions);
el("job-contract").addEventListener("change",()=>options("job-site",assignedSites(records,value("job-contract")),"Choose assigned site"));
el("report-contract").addEventListener("change",()=>options("report-site",assignedSites(records,value("report-contract")),"Choose assigned site"));
el("record-filter").addEventListener("change",renderRecords);
function renderRecords(){const list=records[value("record-filter")];el("record-list").replaceChildren(...(list.length?list.map(r=>card(r.label||"Assigned site",r.id+(r.parentId?" · Parent "+nameOf(r.parentId):"")+(r.relatedId?" · "+nameOf(r.relatedId):""))):[make("p","No loaded records.","muted")]));}
function selectJob(job){if(busy)return;set("job-selected",job.jobId);currentJob=job;renderJob(job);switchTab("jobs");}
function renderJobs(){const items=jobs.map(j=>card(nameOf(j.contractId)+" · "+nameOf(j.siteId),j.serviceDate+" · "+j.status+" · "+j.resolvedRequiredChecks+"/"+j.totalRequiredChecks+" checks","Open job",()=>selectJob(j)));el("job-list").replaceChildren(...(items.length?items:[make("p","No loaded jobs.","muted")]));el("overview-jobs").replaceChildren(...(jobs.slice(0,5).map(j=>card(nameOf(j.contractId),j.serviceDate+" · "+j.status+" · "+j.readinessStatus,"Open job",()=>selectJob(j)))));if(!jobs.length)el("overview-jobs").append(make("p","No loaded jobs.","muted"));}
function renderJob(job){
 set("job-reference","");
 const n=el("job-details");n.replaceChildren(card(job.status+" · "+job.readinessStatus,nameOf(job.contractId)+" / "+nameOf(job.siteId)+" · "+job.resolvedRequiredChecks+"/"+job.totalRequiredChecks+" required checks"));
 for(const c of job.readiness?.checkResults||[]){const row=card(c.label,c.status+(c.blocking?" · Blocking":""));n.append(row);}
}
function overview(){el("metrics").replaceChildren(...[...kinds.slice(0,4).map(k=>[names[k],records[k].length]),["Jobs",jobs.length],["Ready jobs",jobs.filter(j=>j.readinessStatus==="ready").length]].map(([label,n])=>{const c=make("div",undefined,"metric");c.append(make("small",label),make("strong",n));return c;}));el("page-note").textContent=Object.values(cursors).some(Boolean)?"More records are available. Load next pages to expand the selectors and counts.":"No additional pages reported for loaded lists.";refreshOptions();renderRecords();renderJobs();}
async function loadPages(append=false){
 // Sequential requests deliberately stay within the shared rate budget.
 const nextRecords=append?Object.fromEntries(kinds.map(k=>[k,[...records[k]]])):Object.fromEntries(kinds.map(k=>[k,[]]));let nextJobs=append?[...jobs]:[];const nextCursors=append?{...cursors}:{};
 for(const k of [...kinds,"jobs"]){
  if(append&&!cursors[k])continue;
  const base=k==="jobs"?"/workspace/jobs":"/workspace/records-by-kind/"+k;
  const page=await read(base+(append?"?cursor="+uuid(cursors[k]):""));
  if(!page||!Array.isArray(page.items)||page.items.length>50)throw Error("Unexpected page response.");
  if(k==="jobs")nextJobs=[...nextJobs,...page.items];else nextRecords[k]=[...nextRecords[k],...page.items];
  nextCursors[k]=page.nextCursor?uuid(page.nextCursor):null;
 }
 records=nextRecords;jobs=nextJobs;cursors=nextCursors;overview();
}
function saveJob(job){currentJob=job;set("job-selected",job.jobId);jobs=[job,...jobs.filter(j=>j.jobId!==job.jobId)];renderJob(job);overview();}
function renderMappings(){el("mapping-list").replaceChildren(...mappings.map((m,i)=>card(m.amount+" AUD · "+m.bucket,(m.siteId?nameOf(m.siteId)+" · ":"")+m.sourceRowKey,"Remove mapping",()=>{if(!busy){mappings=mappings.filter((_,j)=>j!==i);renderMappings();}})));if(mappings.length)el("mapping-list").append(make("p","Mapped instructions: "+mappings.length+" · "+decimal(mappings.reduce((n,m)=>n+cents(m.amount),0n))+" AUD","muted"));}
function updateBaseline(data){for(const [id,k] of [["baseline-version","versionId"],["baseline-start","periodStart"],["baseline-end","periodEnd"],["baseline-price","price"],["baseline-tax","taxBasis"],["baseline-billing","billingBasis"],["baseline-evidence","evidenceDigest"]])if(typeof data[k]==="string")set(id,data[k]);show("baseline-result",data);}
function updateAllocation(data){show("allocation-result",data);if(data.proposalId&&data.evidenceDigest){set("proposal-id",data.proposalId);set("proposal-digest",data.evidenceDigest);}}
function report(data){const result=el("report-result");result.replaceChildren();const out=data.outputs||data.summary?.outputs||data;result.append(make("strong","Management calculation · "+(out.completeness||data.completeness||"not stated")));for(const [title,k] of [["Revenue","revenue"],["Confirmed site payroll cost","deliveryCost"],["Indicative contribution","indicativeContribution"],["Definitive contribution","contribution"],["Margin percentage","marginPercent"]])result.append(make("p",title+": "+(out[k]===null||out[k]===undefined?"Not available":String(out[k])+(k==="marginPercent"?"%":" "+(out.currency||"")))));for(const note of out.limitations||[])result.append(make("p",note,"muted"));if(data.sourceTrace?.digest){result.append(make("p","Source receipt SHA-256: "+data.sourceTrace.digest),make("p","Reviewed invoice lines: "+data.sourceTrace.reviewedInvoiceLineCount+" / "+data.sourceTrace.invoiceLineCount+" · Site allocation lines: "+data.sourceTrace.allocationLineCount));}else if(data.sourceTrace?.status==="captured")result.append(make("p","Read the saved calculation to view its source receipt.","muted"));else result.append(make("p","Historical source receipt unavailable.","muted"));result.append(make("details",""));const d=result.lastElementChild;d.append(make("summary","View exact API response"),make("pre",JSON.stringify(data,null,2)));if(data.id)set("report-id",data.id);}
const recordBody=()=>{const kind=value("record-kind");return {confirm:true,kind,parentId:kind==="business"?null:uid("record-parent"),relatedId:["contract","contract_site"].includes(kind)?uid("record-related"):null,label:kind==="contract_site"?null:required("record-label","Record alias")};};
const baselinePath=()=>"/workspace/contracts/"+uid("baseline-contract")+"/versions/"+uid("baseline-order");
const intakePath=()=>"/payroll/intakes/"+uid("intake-batch")+"/orders/"+uid("intake-order");
const allocationPath=()=>"/payroll/pools/"+uid("allocation-pool")+"/allocations/"+uid("allocation-run");
const source=()=>parseMinimizedRows(value("source-rows"));
const intakeBody=()=>{const s=source();return {poolId:uid("intake-pool"),sourceNamespace:uid("intake-namespace"),controlTotal:s.controlTotal,rowCount:s.rows.length,authorityDigest:evidence("intake-authority"),policyDigest:evidence("intake-policy"),controlDigest:evidence("intake-control"),rows:s.rows};};
const newId=id=>{if(!globalThis.crypto?.randomUUID)throw Error("UUID generation requires a secure browser context.");set(id,crypto.randomUUID());};
async function action(name){
 if(name==="clear"){reset();return;}
 if(busy)return;
 busy=true;controller=new AbortController();const start=epoch;
 document.querySelectorAll("[data-action]").forEach(n=>{if(n.dataset.action!=="clear")n.disabled=true;});status("Working…");
 try{
  switch(name){
   case "connect":{
    const ctx=credentials();const identity=await request("/v1/me",undefined,ctx,controller.signal);if(start!==epoch)throw Error("Session changed.");
    session={tenant:ctx.tenant};await loadPages();el("workspace").hidden=false;el("session-note").textContent="Verified synthetic session · "+identity.subject;switchTab("overview");break;
   }
   case "refresh":await loadPages();break;
   case "more":await loadPages(true);break;
   case "record-new":newId("record-id");break;
   case "record-create":{confirmed("record-confirm");const data=await read("/workspace/records/"+uid("record-id"),recordBody());records[data.kind]=[data,...records[data.kind].filter(x=>x.id!==data.id)];set("record-filter",data.kind);overview();break;}
   case "baseline-new":newId("baseline-order");newId("baseline-version");break;
   case "baseline-status":updateBaseline(await read(baselinePath()));break;
   case "baseline-step":{confirmed("baseline-confirm");const [periodStart,periodEnd]=range(value("baseline-start"),value("baseline-end"));updateBaseline(await read(baselinePath(),{confirm:true,step:value("baseline-step"),versionId:uid("baseline-version"),periodStart,periodEnd,price:amount(value("baseline-price")),taxBasis:value("baseline-tax"),billingBasis:value("baseline-billing"),evidenceDigest:evidence("baseline-evidence")}));break;}
   case "job-new":newId("job-id");break;
   case "job-create":confirmed("job-confirm");saveJob(await read("/workspace/jobs/"+uid("job-id"),{confirm:true,action:"create",contractId:uid("job-contract"),siteId:uid("job-site"),serviceDate:date(value("job-date")),evidenceDigest:evidence("job-evidence")}));break;
   case "job-read":saveJob(await read("/workspace/jobs/"+uid("job-selected")));break;
   case "job-reference":{set("job-reference","");const d=await read("/workspace/jobs/"+uid("job-selected")+"/securepay-reference");if(d.mode!=="sandbox"||d.moneyMoved!==false||typeof d.reference!=="string"||d.reference.length>2048)throw Error("Invalid reference response.");set("job-reference",d.reference);break;}
   case "event-new":newId("event-id");break;
   case "job-event":{confirmed("event-confirm");const op=value("job-action"),body={confirm:true,action:op,eventId:uid("event-id"),evidenceDigest:evidence("event-evidence")};if(op==="check"){body.checkId=value("check-id");body.checkStatus=value("check-status");}saveJob(await read("/workspace/jobs/"+uid("job-selected"),body));break;}
   case "source-inspect":{const s=source();show("source-result",{rowCount:s.rows.length,controlTotal:s.controlTotal,currency:"AUD",fileSha256:await checksum(s.canonical)});break;}
   case "source-register":{confirmed("register-confirm");const s=source(),[periodStart,periodEnd]=range(value("source-start"),value("source-end")),sha256=await checksum(s.canonical);if(start!==epoch)throw Error("Session changed.");const data=await read("/imports",{sourceType:"payroll",fileName:"minimized-payroll-v1.csv",sha256,permissionReference:"reviewed-payroll-authority",periodStart,periodEnd});set("intake-batch",data.batch.id);show("source-result",{batchId:data.batch.id,status:data.batch.status,rowCount:s.rows.length,controlTotal:s.controlTotal,sha256});break;}
   case "intake-new":newId("intake-pool");newId("intake-namespace");newId("intake-order");set("intake-scope","");break;
   case "intake-preview":{const d=await read(intakePath()+"/preview",intakeBody());set("intake-scope",d.scopeDigest);show("intake-result",d);break;}
   case "intake-status":{const d=await read(intakePath());set("intake-scope",d.scopeDigest);set("intake-pool",d.poolId);show("intake-result",d);if(d.status==="source-accepted")set("allocation-pool",d.poolId);break;}
   case "intake-step":{confirmed("intake-confirm");const d=await read(intakePath(),{...intakeBody(),confirm:true,step:value("intake-step"),scopeDigest:evidence("intake-scope")});show("intake-result",d);if(d.status==="source-accepted")set("allocation-pool",d.poolId);break;}
   case "allocation-new":newId("allocation-run");break;
   case "mapping-add":{const m=mappingLine({sourceRowKey:value("mapping-key"),bucket:value("mapping-bucket"),siteId:value("mapping-site"),amount:value("mapping-amount"),evidenceRef:value("mapping-evidence")});if(mappings.length>=400||mappings.some(x=>mappingKey(x)===mappingKey(m)))throw Error("Duplicate or excessive mapping instructions.");decimal([...mappings,m].reduce((n,x)=>n+cents(x.amount),0n));mappings.push(m);renderMappings();break;}
   case "allocation-status":updateAllocation(await read(allocationPath()));break;
   case "allocation-build":confirmed("allocation-confirm");updateAllocation(await read(allocationPath(),{confirm:true,lines:mappings}));break;
   case "proposal-read":{const d=await read("/payroll/proposals/"+uid("proposal-id"));set("proposal-digest",d.evidenceDigest);show("proposal-result",d);break;}
   case "proposal-confirm":confirmed("proposal-confirm");show("proposal-result",await read("/payroll/proposals/"+uid("proposal-id")+"/confirm",{confirm:true,evidenceDigest:evidence("proposal-digest")}));break;
   case "report-build":{const [periodStart,periodEnd]=range(value("report-start"),value("report-end"));report(await read("/calculations",{contractId:uid("report-contract"),siteId:uid("report-site"),periodStart,periodEnd}));break;}
   case "report-read":report(await read("/calculations/"+uid("report-id")));break;
   case "report-export":confirmed("report-confirm");show("report-result",await read("/calculations/"+uid("report-id")+"/export",{purpose:value("report-purpose")}));break;
   case "invoice-register":{
    confirmed("invoice-register-confirm");const f=el("invoice-file").files[0];if(!f||f.size<1||f.size>65536)throw Error("Choose 1–65536 byte synthetic CSV.");
    const [periodStart,periodEnd]=range(value("invoice-start"),value("invoice-end")),bytes=await f.arrayBuffer();
    const sha256=[...new Uint8Array(await crypto.subtle.digest("SHA-256",bytes))].map(x=>x.toString(16).padStart(2,"0")).join("");
    if(start!==epoch)throw Error("Session changed.");
    const d=await read("/imports",{sourceType:"customer_invoice",fileName:"synthetic-invoice.csv",sha256,permissionReference:"reviewed-invoice-authority",periodStart,periodEnd});
    set("invoice-batch",d.batch.id);show("invoice-source-result",d);break;
   }
   case "invoice-upload":{
    confirmed("invoice-upload-confirm");const f=el("invoice-file").files[0];if(!f||f.size<1||f.size>65536)throw Error("Choose the same synthetic CSV.");
    const target=tenantPath(session.tenant,"/imports/"+uid("invoice-batch")+"/file");
    const res=await fetch(target,{method:"POST",headers:{Authorization:"Bearer "+credentials().token,"Content-Type":"text/csv"},body:f,credentials:"omit",cache:"no-store",redirect:"error",signal:controller.signal});
    if(start!==epoch)throw Error("Session changed.");
    const d=await res.json();if(!res.ok)throw Error("Upload denied or result unknown. Reconcile the exact registered batch before retrying. HTTP "+res.status);
    show("invoice-source-result",d);el("invoice-file").value="";break;
   }
   case "invoice-promote":confirmed("invoice-promote-confirm");show("invoice-source-result",await read("/imports/"+uid("invoice-batch")+"/file/approve",{}));break;
   case "invoice-new":acceptedInvoice=null;newId("invoice-order");set("invoice-scope","");break;
   case "invoice-report-scope":{if(!acceptedInvoice||acceptedInvoice.batchId!==uid("invoice-batch")||acceptedInvoice.orderId!==uid("invoice-order"))throw Error("Read an accepted invoice review first.");const selected=el("invoice-report-line").value;const scope=acceptedInvoice.lines.find(x=>x.rawRowId===selected);if(!scope)throw Error("Choose a reviewed invoice row.");if(!records.contract.some(x=>x.id===scope.contractId)||!assignedSites(records,scope.contractId).some(x=>x.id===scope.siteId))throw Error("Load the relevant workspace records and site assignments before continuing.");set("report-contract",scope.contractId);options("report-site",assignedSites(records,scope.contractId),"Choose assigned site");set("report-site",scope.siteId);set("report-start",date(scope.periodStart));set("report-end",date(scope.periodEnd));el("report-result").replaceChildren();set("report-id","");switchTab("reports");status("Reviewed scope selected. Confirm payroll evidence and build a new calculation; no calculation has been run.");return;}
   case "invoice-preview":
   case "invoice-status":
   case "invoice-step":{
    const path="/invoice-intakes/"+uid("invoice-batch")+"/orders/"+uid("invoice-order");
    acceptedInvoice=null;options("invoice-report-line",[],"Choose accepted source line");let d;
    if(name==="invoice-status")d=await read(path);
    else{
     const count=Number(value("invoice-count"));
     if(!Number.isSafeInteger(count)||count<1||count>200)throw Error("Enter the independent source row count (1–200).");
     const body={controlTotal:amount(value("invoice-total")),rowCount:count,evidenceDigest:evidence("invoice-evidence")};
     if(name==="invoice-preview")d=await read(path+"/preview",body);
     else{confirmed("invoice-review-confirm");d=await read(path,{...body,scopeDigest:evidence("invoice-scope"),step:value("invoice-step"),confirm:true});}
    }
    set("invoice-total",d.controlTotal);set("invoice-count",d.rowCount);set("invoice-evidence",d.evidenceDigest);set("invoice-scope",d.scopeDigest);
    if(d.status==="accepted"&&Array.isArray(d.lines)&&d.lines.length>0){acceptedInvoice={batchId:uid("invoice-batch"),orderId:uid("invoice-order"),lines:d.lines};options("invoice-report-line",d.lines.map(x=>({id:x.rawRowId,label:"Row "+x.rowNumber+" · "+x.amount+" AUD"})),"Choose accepted source line");}
    show("invoice-review-result",d);break;
   }
   default:throw Error("Unsupported action.");
  }
  if(start===epoch)status("Completed. Review the returned state before continuing.");
 }catch(e){if(start===epoch){if(name==="connect"){session=null;el("workspace").hidden=true;el("session-note").textContent="Not connected.";}status(e.message||"Request unavailable.",true);}}
 finally{busy=false;controller=null;document.querySelectorAll("[data-action]").forEach(n=>n.disabled=false);}
}
document.querySelectorAll("[data-action]").forEach(n=>n.addEventListener("click",()=>action(n.dataset.action)));
