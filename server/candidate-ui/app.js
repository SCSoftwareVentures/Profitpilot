"use strict";
const el=id=>document.getElementById(id),uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,sha=/^[a-f0-9]{64}$/;
let busy=false,epoch=0,controller=null;
const clean=id=>{const v=el(id).value.trim().toLowerCase();if(!uuid.test(v))throw Error("Enter a valid "+id+" UUID.");return v;};
const digest=id=>{const v=el(id).value.trim();if(!sha.test(v))throw Error("Enter the exact "+id+" digest.");return v;};
const checked=id=>{if(!el(id).checked)throw Error("Explicit confirmation is required.");};
function clear(){epoch++;controller?.abort();controller=null;for(const node of document.querySelectorAll("input")){if(node.type==="checkbox")node.checked=false;else node.value="";}el("result").textContent="";el("status").textContent="Session cleared.";}
el("clear").addEventListener("click",clear);
el("new-order").addEventListener("click",()=>{if(!busy)el("order").value=crypto.randomUUID();});
el("new-case").addEventListener("click",()=>{if(!busy)el("case").value=crypto.randomUUID();});
el("new-correction").addEventListener("click",()=>{if(!busy)el("correction-order").value=crypto.randomUUID();});
el("new-delivery").addEventListener("click",()=>{if(!busy)el("delivery-order").value=crypto.randomUUID();});
el("new-receipt").addEventListener("click",()=>{if(!busy)el("receipt-review").value=crypto.randomUUID();});
window.addEventListener("pagehide",clear);
async function operation(action){
 if(busy)return;
 const current=++epoch;
 let active=false;
 el("result").textContent="";
 try{
  const t=clean("tenant"),token=el("token").value.trim();
  if(!token||token.length>8192||/\s/.test(token))throw Error("Enter a current synthetic access token.");
  let path,body;
  switch(action){
   case "submit":path="/payroll/runs/"+clean("run")+"/submit";body={submit:true};break;
   case "review":path="/payroll/proposals/"+clean("proposal");break;
   case "confirm":checked("payroll-confirm");path="/payroll/proposals/"+clean("proposal")+"/confirm";body={confirm:true,evidenceDigest:digest("digest")};el("payroll-confirm").checked=false;break;
   case "account":path="/privacy/account";break;
   case "correct":checked("email-confirm");path="/privacy/account/correct-email";body={confirm:true};el("email-confirm").checked=false;break;
   case "preview":path="/privacy/invoices/"+clean("batch")+"/disposal-preview";body={};break;
   case "disposal":checked("dispose-confirm");path="/privacy/invoices/"+clean("batch")+"/disposals/"+clean("order");body={step:el("step").value,scopeDigest:digest("scope"),confirm:true};el("dispose-confirm").checked=false;break;
   case "case-status":path="/privacy/cases/"+clean("case");break;
   case "case-action":{
    checked("case-confirm");path="/privacy/cases/"+clean("case");
    const action=el("case-action").value;
    body={action,confirm:true};
    if(["request","intake"].includes(action))body.kind=el("case-kind").value;
    if(["resolve","refuse"].includes(action))body.reasonCode=el("case-reason").value;
    if(["intake","resolve","refuse"].includes(action))body.evidenceDigest=digest("case-evidence");
    el("case-confirm").checked=false;break;
   }
   case "correction-preview":path="/payroll/runs/"+clean("correction-old")+"/correction-preview";body={proposalId:clean("correction-proposal"),reason:el("correction-reason").value,authorityEvidenceDigest:digest("correction-evidence")};break;
   case "correction-status":path="/payroll/corrections/"+clean("correction-order");break;
   case "correction-step":{
    checked("correction-confirm");path="/payroll/corrections/"+clean("correction-order");
    const step=el("correction-step").value;
    body={oldRunId:clean("correction-old"),proposalId:clean("correction-proposal"),reason:el("correction-reason").value,authorityEvidenceDigest:digest("correction-evidence"),scopeDigest:digest("correction-scope"),step,confirm:true};
    if(step==="consume")body.proposalDigest=digest("correction-digest");
    el("correction-confirm").checked=false;break;
   }
   case "delivery-preview":
   case "delivery-status":
   case "delivery-step":{
    path="/privacy/cases/"+clean("delivery-case")+"/deliveries/"+clean("delivery-order");
    if(action!=="delivery-status"){
      body={recipientType:el("delivery-recipient-type").value,recipientKeyDigest:digest("delivery-recipient"),senderKeyDigest:digest("delivery-sender"),authorityDigest:digest("delivery-authority"),redactionDigest:digest("delivery-redaction"),responseDigest:digest("delivery-response"),envelopeDigest:digest("delivery-envelope")};
      if(action==="delivery-preview")path+="/preview";
      else{checked("delivery-confirm");body.step=el("delivery-step").value;body.scopeDigest=digest("delivery-scope");body.confirm=true;el("delivery-confirm").checked=false;}
    }
    break;
   }
   case "receipt-preview":
   case "receipt-status":
   case "receipt-step":{
    path="/privacy/cases/"+clean("receipt-case")+"/deliveries/"+clean("receipt-release")+"/receipts/"+clean("receipt-review");
    if(action!=="receipt-status"){
     body={challengeDigest:digest("receipt-challenge"),receiptDigest:digest("receipt-digest"),receiptKeyDigest:digest("receipt-signer"),verificationEvidenceDigest:digest("receipt-evidence")};
     if(action==="receipt-preview")path+="/preview";
     else{checked("receipt-confirm");body.step=el("receipt-step").value;body.scopeDigest=digest("receipt-scope");body.confirm=true;el("receipt-confirm").checked=false;}
    }break;
   }
   default:throw Error("Unknown operation.");
  }
  busy=true;active=true;controller=new AbortController();
  for(const b of document.querySelectorAll("button[data-operation],#new-order,#new-case,#new-correction,#new-delivery,#new-receipt"))b.disabled=true;
  el("status").textContent="Request in progress.";
  const res=await fetch("/v1/tenants/"+t+path,{method:body===undefined?"GET":"POST",headers:{Authorization:"Bearer "+token,...(body===undefined?{}:{"Content-Type":"application/json"})},credentials:"omit",cache:"no-store",redirect:"error",signal:controller.signal,body:body===undefined?undefined:JSON.stringify(body)});
  const data=await res.json();
  if(current!==epoch)return;
  el("status").textContent=(res.ok?"Accepted":"Denied")+" · HTTP "+res.status;
  el("result").textContent=JSON.stringify(data,null,2);
  if(res.ok&&["submit","review"].includes(action)&&uuid.test(data.proposalId||"")&&sha.test(data.evidenceDigest||"")){
   el("proposal").value=data.proposalId;el("digest").value=data.evidenceDigest;
  }
  if(res.ok&&action==="preview"&&sha.test(data.scopeDigest||""))el("scope").value=data.scopeDigest;
  if(res.ok&&["receipt-preview","receipt-status"].includes(action)&&sha.test(data.scopeDigest||"")){el("receipt-scope").value=data.scopeDigest;el("receipt-confirm").checked=false;}
  if(res.ok&&["delivery-preview","delivery-status"].includes(action)&&sha.test(data.scopeDigest||"")){el("delivery-scope").value=data.scopeDigest;el("delivery-confirm").checked=false;}
  if(res.ok&&action==="correction-preview"&&sha.test(data.scopeDigest||"")&&sha.test(data.proposalDigest||"")){
   el("correction-scope").value=data.scopeDigest;el("correction-digest").value=data.proposalDigest;
  }
  if(res.ok&&action==="correction-status"&&uuid.test(data.oldRunId||"")&&uuid.test(data.proposalId||"")&&sha.test(data.scopeDigest||"")&&sha.test(data.proposalDigest||"")&&sha.test(data.authorityEvidenceDigest||"")){
   el("correction-old").value=data.oldRunId;el("correction-proposal").value=data.proposalId;el("correction-scope").value=data.scopeDigest;el("correction-digest").value=data.proposalDigest;el("correction-evidence").value=data.authorityEvidenceDigest;el("correction-reason").value=data.reason;
   el("correction-confirm").checked=false;
  }
 }catch(e){if(current===epoch)el("status").textContent=e.name==="AbortError"?"Request cancelled.":(active?"Request unavailable.":e.message);}
 finally{if(active){busy=false;controller=null;for(const b of document.querySelectorAll("button[data-operation],#new-order,#new-case,#new-correction,#new-delivery,#new-receipt"))b.disabled=false;}}
}
for(const node of document.querySelectorAll("button[data-operation]"))node.addEventListener("click",()=>operation(node.dataset.operation));