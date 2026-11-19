"use strict";
const $=id=>document.getElementById(id);
const labels={activeTenantIncidents:"Active tenant incidents",temporarilyContainedActors:"Temporarily restricted accounts",identitySecurityEvents24h:"Identity security events (24h)",pendingOrRetryableScans:"Pending or retryable scans",processingScans:"Processing scans",pendingOrProcessingPromotions:"Pending or processing approvals",failedPromotions:"Failed promotions"};
let token=null,cursor=null,timer=null,controller=null,generation=0;
function clear(message){$("status").textContent=message;$("time").textContent="";$("counts").replaceChildren();$("incidentRows").replaceChildren();cursor=null;$("next").disabled=true;}
function disconnect(){generation++;token=null;controller?.abort();controller=null;clearInterval(timer);timer=null;$("token").value="";$("refresh").disabled=true;clear("Disconnected");}
function render(report){
 if(report.catalogVerified!==true){clear("SECURITY CATALOGUE DRIFT — operational data withheld.");return;}
 $("status").textContent=report.status==="containment_active"?"Containment active":"No active containment reported";
 $("time").textContent="Observed: "+new Date(report.observedAt).toLocaleString();
 $("counts").replaceChildren(...Object.entries(labels).map(([key,label])=>{const card=document.createElement("div"),dt=document.createElement("dt"),dd=document.createElement("dd");dt.textContent=label;dd.textContent=String(report.counts[key]);card.append(dt,dd);return card;}));
 $("incidentRows").replaceChildren(...report.activeIncidents.map(i=>{const row=document.createElement("tr");for(const v of [i.incidentId,i.tenantId,i.category,new Date(i.activatedAt).toLocaleString()]){const cell=document.createElement("td");cell.textContent=v;row.append(cell);}return row;}));
 cursor=report.nextCursor;$("next").disabled=!cursor;
}
async function refresh(after=null){
 if(!token||controller)return;
 const current=generation,c=new AbortController();controller=c;
 try{
  const url="/snapshot?limit=50"+(after?"&cursor="+encodeURIComponent(after):"");
  const response=await fetch(url,{headers:{Authorization:"Bearer "+token},cache:"no-store",credentials:"omit",redirect:"error",signal:AbortSignal.any([c.signal,AbortSignal.timeout(7000)])});
  if(current!==generation)return;
  if(response.status===401){disconnect();$("status").textContent="Access denied. Reconnect with an approved token.";return;}
  const data=await response.json();
  if(current!==generation)return;
  if((!response.ok&&data.catalogVerified!==false)||data.schemaVersion!==1)throw Error("Unavailable");
  render(data);
 }catch{if(current===generation)clear("Observations unavailable — no current security assurance.");}
 finally{if(controller===c)controller=null;}
}
$("connect").addEventListener("submit",e=>{e.preventDefault();const candidate=$("token").value;disconnect();if(!/^[a-f0-9]{64}$/.test(candidate)){clear("Invalid token format.");return;}token=candidate;$("refresh").disabled=false;void refresh();timer=setInterval(()=>void refresh(),15000);});
$("disconnect").addEventListener("click",disconnect);
$("refresh").addEventListener("click",()=>void refresh());
$("next").addEventListener("click",()=>{if(cursor)void refresh(cursor);});
window.addEventListener("pagehide",disconnect);