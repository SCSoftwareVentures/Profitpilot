// Sandbox-only browser portal. No external scripts, cookies, token persistence,
// or automatic payment retries. The customer JWT is supplied through test MFA.
import {createHash} from "node:crypto";
const css="body{font:16px system-ui;background:#f3f6fa;color:#18263a;margin:0}main{max-width:640px;margin:auto;padding:24px}section{background:white;border:1px solid #d8e1ec;padding:20px;border-radius:12px;margin-top:16px}label{display:block;margin:12px 0 4px}input:not([type=checkbox]),select{box-sizing:border-box;width:100%;padding:12px;border:1px solid #a8b7cc;border-radius:6px;font:inherit}button{font:inherit;padding:12px 16px;border:0;border-radius:6px;background:#174b87;color:white;margin:12px 8px 0 0}button:disabled{opacity:.45}p{line-height:1.5;overflow-wrap:anywhere}.notice{border-left:4px solid #a66c13;background:#fff3db;padding:12px}.amount{font-size:30px;font-weight:700}dt{font-weight:600}dd{margin:0 0 12px}iframe{width:100%;min-height:640px;border:1px solid #d8e1ec;border-radius:8px}";
function page(title,markup,script){
 const hash=createHash("sha256").update(script).digest("base64");
 const csp="default-src 'none'; script-src 'sha256-"+hash+"'; style-src 'unsafe-inline'; connect-src 'self'; frame-src 'self' about:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
 return {csp,html:"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>"+title+"</title><style>"+css+"</style></head><body><main>"+markup+"</main><script>"+script+"</script></body></html>"};
}
const portalScript=String.raw`
(()=>{
 const $=id=>document.getElementById(id),uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
 let token="",scope=null,view=null,busy=false,attemptKey=null,grant=null;
 const message=s=>{$("message").textContent=s;};
 function clearView(){view=null;scope=null;grant=null;attemptKey=null;$("details").hidden=true;$("pin").value="";$("confirm").checked=false;$("reserve").disabled=true;}
 function controls(){for(const id of ["load","clear","grant","set-pin"])$(id).disabled=busy;$("reserve").disabled=busy||!view||view.status!=="approved"||view.fundingStatus!=="funded"||view.requestStatus!==null||!$("confirm").checked;}
 async function post(path,body){const r=await fetch("/v1/securepay"+path,{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+token},body:JSON.stringify(body),cache:"no-store",credentials:"omit",redirect:"error"});let x;try{x=await r.json();}catch{throw Error("Invalid service response");}return {code:r.status,data:x};}
 function cents(v){if(typeof v!=="string"||!/^[1-9][0-9]{0,18}$/.test(v))throw Error("Invalid amount");const n=BigInt(v);return "AUD $"+String(n/100n)+"."+String(n%100n).padStart(2,"0");}
 function valid(v,m){return v?.mode==="sandbox"&&v.moneyMoved===false&&v.milestoneId===m&&typeof v.amountCents==="string";}
 $("load").addEventListener("click",async()=>{
  if(busy)return;const t=$("tenant").value.trim(),m=$("milestone").value.trim(),supplied=$("token").value.trim();$("token").value="";
  if(supplied)token=supplied;clearView();
  if(!uuid.test(t)||!uuid.test(m)||!token){message("Enter the tenant, milestone and sandbox MFA token.");return;}
  busy=true;controls();
  try{const r=await post("/tenants/"+t+"/milestones/"+m+"/view",{});if(r.code!==200||!valid(r.data,m)){message("Unable to access this milestone. Check your identity and session.");return;}
   view=r.data;scope={t,m};$("amount").textContent=cents(view.amountCents);$("state").textContent=view.status;$("funding").textContent=view.fundingStatus;$("request").textContent=view.requestStatus??"None";$("details").hidden=false;message("Review the amount and current status before authorising.");
  }catch{message("Unable to load the milestone. No payment was submitted.");}finally{busy=false;controls();}
 });
 $("confirm").addEventListener("change",controls);
 $("reserve").addEventListener("click",async()=>{
  if(busy||!scope||!view||$("reserve").disabled)return;
  const pin=$("pin").value;$("pin").value="";
  if(!/^[0-9]{6}$/.test(pin)){message("Enter a six-digit PIN.");return;}
  if(BigInt(view.amountCents)>BigInt(Number.MAX_SAFE_INTEGER)){message("Amount exceeds supported limits.");return;}
  const current=scope,expected=Number(view.amountCents);attemptKey=attemptKey??crypto.randomUUID();
  busy=true;controls();
  try{const r=await post("/tenants/"+current.t+"/milestones/"+current.m+"/reserve",{pin,expectedAmountCents:expected,idempotencyKey:attemptKey});
   if(r.code===202&&r.data?.mode==="sandbox"&&r.data.moneyMoved===false&&r.data.status==="reserved"&&r.data.milestoneId===current.m&&r.data.amountCents===String(expected)){message("Authorisation reserved in sandbox. No money moved. Reload the milestone for its current status.");}
   else message("Authorisation not confirmed. Reload the milestone before taking any further action.");
  }catch{message("Outcome uncertain. Reload the milestone to reconcile; do not retry blindly.");}
  finally{clearView();busy=false;controls();}
 });
 $("grant").addEventListener("click",async()=>{
  if(busy||!scope)return;const stepUpToken=$("step-up").value.trim(),purpose=$("purpose").value;$("step-up").value="";grant=null;
  if(!stepUpToken){message("A separate recent MFA step-up token is required.");return;}
  busy=true;controls();try{const r=await post("/tenants/"+scope.t+"/pin/grant",{purpose,stepUpToken});
   if(r.code===201&&r.data?.mode==="sandbox"&&r.data.status==="grant_issued"&&uuid.test(r.data.grantRef)){grant={ref:r.data.grantRef,purpose};message("Short-lived PIN grant issued. Enter a new PIN.");}else message("PIN grant unavailable or denied.");
  }catch{message("Grant outcome uncertain. Obtain a fresh step-up token.");}finally{busy=false;controls();}
 });
 $("set-pin").addEventListener("click",async()=>{
  if(busy||!scope||!grant){message("Load a milestone and obtain a PIN grant first.");return;}
  const pin=$("new-pin").value;$("new-pin").value="";if(!/^[0-9]{6}$/.test(pin)){message("Enter a six-digit PIN.");return;}
  const g=grant;grant=null;busy=true;controls();
  try{const r=await post("/tenants/"+scope.t+"/pin",{pin,purpose:g.purpose,grantRef:g.ref});message(r.code===200&&r.data?.status==="pin_updated"?"PIN updated. Obtain fresh authentication if required.":"PIN update not confirmed. Reauthenticate before continuing.");}catch{message("PIN update outcome uncertain. Reauthenticate before continuing.");}
  finally{token="";clearView();busy=false;controls();}
 });
 $("clear").addEventListener("click",()=>{if(busy)return;token="";clearView();for(const id of ["token","step-up","new-pin","tenant","milestone"])$(id).value="";message("Session cleared.");});
 controls();
})();
`;
export function customerPortalPage(){
 return page("SecurePay customer portal",'<h1>SecurePay customer portal</h1><p class="notice">SANDBOX ONLY. No money moves. Use test credentials only.</p><section><h2>Access your milestone</h2><label for="tenant">Tenant reference</label><input id="tenant" autocomplete="off"><label for="milestone">Milestone reference</label><input id="milestone" autocomplete="off"><label for="token">Sandbox MFA access token</label><input id="token" type="password" autocomplete="off"><button id="load">Load milestone</button><button id="clear">Clear session</button></section><section id="details" hidden><h2>Payment details</h2><p class="amount" id="amount"></p><dl><dt>Milestone status</dt><dd id="state"></dd><dt>Funding status</dt><dd id="funding"></dd><dt>Release request</dt><dd id="request"></dd></dl><p>Only authorise after inspecting the completed work and confirming the amount. Disputed or unfunded work cannot be released.</p><label><input type="checkbox" id="confirm"> I have reviewed the work and exact amount displayed.</label><label for="pin">SecurePay PIN</label><input id="pin" type="password" inputmode="numeric" maxlength="6" autocomplete="off"><button id="reserve" disabled>Authorise sandbox release</button><h3>Set or recover PIN</h3><label for="purpose">Purpose</label><select id="purpose"><option value="enroll">Enrol PIN</option><option value="recover">Recover PIN</option></select><label for="step-up">Separate MFA step-up token</label><input id="step-up" type="password" autocomplete="off"><button id="grant">Request grant</button><label for="new-pin">New PIN</label><input id="new-pin" type="password" maxlength="6" inputmode="numeric" autocomplete="off"><button id="set-pin">Set PIN</button></section><p role="status" aria-live="polite" id="message"></p>',portalScript);
}
export function sendPortalPage(res,document){
 return res.set({"Cache-Control":"no-store","Content-Security-Policy":document.csp,"X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer","X-Frame-Options":"DENY"}).type("html").send(document.html);
}
