// Isolated W3C WebDriver harness. Real Firefox and GTK WebKit, no external
// URLs, npm additions or persistent profiles. Tests actual generated Blob
// bytes; native download-manager behaviour is certified only by the CDP harness.
import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {createServer} from "node:net";
import {setTimeout as sleep} from "node:timers/promises";
async function until(fn,label,timeout=16000){const end=Date.now()+timeout;while(Date.now()<end){if(await fn())return;await sleep(100);}throw Error("Browser condition unavailable: "+label);}
async function unusedPort(){const probe=createServer();await new Promise((resolve,reject)=>{probe.once("error",reject);probe.listen(0,"127.0.0.1",resolve);});const port=probe.address().port;await new Promise(resolve=>probe.close(resolve));return port;}
export async function verifyFinanceWebDriver({base,tenant,token,run,traceDigest}){
 const kind=process.env.PROFITPILOT_CI_BROWSER,driver=process.env.PROFITPILOT_CI_WEBDRIVER;
 if(!/^http:\/\/127\.0\.0\.1:\d+$/.test(base)||!driver||!["firefox","webkit"].includes(kind)||!process.env.TEST_ADMIN_DATABASE_URL||!process.env.TEST_APP_DATABASE_URL)throw Error("Disposable CI WebDriver required.");
 const port=await unusedPort(),endpoint="http://127.0.0.1:"+port;
 const proc=spawn(driver,kind==="firefox"?["--host","127.0.0.1","--port",String(port)]:["--host=127.0.0.1","--port="+port],{stdio:"ignore",detached:true});
 let launchError,session,closing=false;proc.on("error",e=>{launchError=e;});
 const command=async(method,path,body)=>{
  let res;try{res=await fetch(endpoint+path,{method,headers:{...(body===undefined?{}:{"Content-Type":"application/json"})},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(path==="/session"?60000:25000)});}catch(e){throw Error("WebDriver transport failed: "+method+" "+path.replace(/\/session\/[^/]+/,"/session")+" ("+e.name+")");}
  const x=await res.json();
  if(!res.ok||x.value?.error)throw Error("WebDriver "+method+" "+path.replace(/\/session\/[^/]+/,"/session")+(x.value?.error?": "+x.value.error:" failed"));
  return x.value;
 };
 const evaluate=(script,args=[])=>command("POST","/session/"+session+"/execute/sync",{script,args});
 const evaluateAsync=(script,args=[])=>command("POST","/session/"+session+"/execute/async",{script,args});
 const call=(path,body)=>command("POST","/session/"+session+path,body);
 try{
  await until(async()=>{if(launchError||proc.exitCode!==null)throw Error(kind+" driver failed to start");try{await command("GET","/status");return true;}catch{return false;}},"driver status");
  const capability=kind==="firefox"?{browserName:"firefox","moz:firefoxOptions":{args:["-headless"]}}:{browserName:"MiniBrowser"};
  const result=await command("POST","/session",{capabilities:{alwaysMatch:capability}});
  session=result.sessionId;assert.ok(typeof session==="string"&&session.length>0);
  await call("/timeouts",{script:15000,pageLoad:20000,implicit:0});
  await call("/window/rect",{width:480,height:900,x:0,y:0});
  await call("/url",{url:base+"/candidate/workspace/"});
  await until(()=>evaluate("return document.readyState==='complete' && document.documentElement.dataset.workspaceReady==='true'"),"workspace module initialization");
  await evaluate("document.getElementById('tenant').value=arguments[0];document.getElementById('token').value=arguments[1];document.querySelector('[data-action=connect]').click();",[tenant,token]);
  await until(async()=>{const state=await evaluate("return {visible:!document.getElementById('workspace').hidden,busy:document.querySelector('[data-action=connect]').disabled,failed:document.getElementById('status').classList.contains('error'),reason:document.getElementById('status').textContent};");if(state.failed&&!state.busy){const reason=state.reason;throw Error("Workspace session failed: "+(/HTTP 429/.test(reason)?"rate restricted":/Authority denied/.test(reason)?"authority denied":/Unable to read/.test(reason)?"network failure":/Response unavailable/.test(reason)?"invalid response":/Unexpected page/.test(reason)?"invalid page":/Session changed/.test(reason)?"session changed":"other application error"));}return state.visible&&!state.busy;},"authenticated workspace",25000);
  assert.equal(await evaluate("return document.querySelector('[role=tab][aria-selected=true]').id"),"tab-overview");
  await evaluate("const tab=document.getElementById('tab-overview');tab.focus();tab.dispatchEvent(new KeyboardEvent('keydown',{key:'End',bubbles:true,cancelable:true}));");
  assert.deepEqual(await evaluate("return [document.activeElement.id,document.getElementById('tab-reports').tabIndex,document.getElementById('tab-overview').tabIndex,document.getElementById('panel-reports').hidden]"),["tab-reports",0,-1,false]);
  await evaluate("document.getElementById('report-id').value=arguments[0];document.querySelector('[data-action=report-read]').click();",[run]);
  await until(()=>evaluate("return !document.querySelector('[data-action=report-read]').disabled && document.getElementById('report-result').textContent.includes(arguments[0]);",[traceDigest]),"real report source receipt");
  const layout=await evaluate("return {width:window.innerWidth,overflow:document.documentElement.scrollWidth>window.innerWidth};");
  assert.ok(layout.width<=520&&layout.width>=300,"narrow real-browser viewport required");
  assert.equal(layout.overflow,false,"no horizontal document overflow");
  assert.equal(await evaluate("return document.getElementById('report-downloads').children.length"),0);
  await evaluate("document.querySelector('[data-action=report-export]').click()");
  await until(()=>evaluate("return !document.querySelector('[data-action=report-export]').disabled && document.getElementById('status').textContent.includes('Explicit confirmation')"),"explicit confirmation");
  await evaluate("const id=document.getElementById('report-id');id.value='';id.dispatchEvent(new Event('input',{bubbles:true}));");
  assert.equal(await evaluate("return document.getElementById('report-result').textContent==='' && document.getElementById('report-downloads').children.length===0"),true);
  await evaluate("document.getElementById('report-id').value=arguments[0];", [run]);
  // Capture the actual generated Blob bytes without weakening CSP or depending
  // on a particular desktop download dialog. Preserve native URL behaviour.
  await evaluate("window.__ciBlobs=[];window.__ciRevoked=[];const create=URL.createObjectURL.bind(URL),revoke=URL.revokeObjectURL.bind(URL);URL.createObjectURL=b=>{const u=create(b);window.__ciBlobs.push({u,b});return u;};URL.revokeObjectURL=u=>{window.__ciRevoked.push(u);return revoke(u);};document.getElementById('report-confirm').checked=true;document.querySelector('[data-action=report-export]').click();");
  await until(()=>evaluate("return document.getElementById('report-downloads').children.length===2 && !document.querySelector('[data-action=report-export]').disabled"),"audited report links");
  const files=await evaluateAsync("const done=arguments[arguments.length-1];Promise.all(window.__ciBlobs.map(async x=>({url:x.u,content:await x.b.text(),type:x.b.type}))).then(done,()=>done(null));");
  assert.ok(Array.isArray(files)&&files.length===2);
  const links=await evaluate("return Array.from(document.querySelectorAll('#report-downloads a')).map(a=>({href:a.href,name:a.download}));");
  assert.deepEqual(links.map(x=>x.name),["profitpilot-management-"+run+".json","profitpilot-management-"+run+".txt"]);
  assert.deepEqual(links.map(x=>x.href),files.map(x=>x.url));
  const data=JSON.parse(files[0].content);
  assert.equal(data.calculationId,run);assert.equal(data.sourceTrace.digest,traceDigest);assert.equal(data.indicativeContribution,"0.20");assert.equal(data.contribution,null);
  assert.match(files[1].content,/Indicative contribution: AUD 0\.20/);
  assert.ok(files.every(x=>!x.content.includes(token)&&!x.content.includes("source_snapshot")));
  await evaluate("document.querySelector('[data-action=clear]').click()");
  assert.equal(await evaluate("return document.getElementById('workspace').hidden && document.getElementById('token').value==='' && document.getElementById('report-downloads').children.length===0"),true);
  assert.deepEqual(await evaluate("return window.__ciRevoked"),files.map(x=>x.url));
  console.log("Real "+kind+" engine, "+layout.width+"px viewport: authenticated report, keyboard navigation, explicit confirmation, exact Blob payload and URL revocation passed");
 }finally{
  if(session)try{await command("DELETE","/session/"+session);}catch{closing=true;}
  if(proc.pid){try{process.kill(-proc.pid,"SIGTERM");}catch{}}
  if(closing)throw Error("Browser session cleanup failed");
 }
}
