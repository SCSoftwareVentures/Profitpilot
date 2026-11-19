// Real Chromium, loopback-only disposable CI. No browser library or runtime
// dependency. The runner's existing browser is used; no external page is visited.
import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {mkdtemp,readFile,readdir,rm,mkdir} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {setTimeout as sleep} from "node:timers/promises";
async function until(fn,label,timeout=12000){const end=Date.now()+timeout;while(Date.now()<end){const x=await fn();if(x)return x;await sleep(100);}throw Error("Browser condition unavailable: "+label);}
export async function verifyFinanceBrowser({base,tenant,token,run,traceDigest}){
 if(!/^http:\/\/127\.0\.0\.1:\d+$/.test(base)||!process.env.PROFITPILOT_CI_CHROME)throw Error("Disposable CI browser required.");
 const root=await mkdtemp(join(tmpdir(),"profitpilot-browser-")),profile=join(root,"profile"),downloads=join(root,"downloads");
 await mkdir(downloads);
 const proc=spawn(process.env.PROFITPILOT_CI_CHROME,["--headless","--no-sandbox","--disable-dev-shm-usage","--disable-background-networking","--disable-sync","--no-first-run","--no-default-browser-check","--remote-debugging-address=127.0.0.1","--remote-debugging-port=0","--user-data-dir="+profile,"about:blank"],{stdio:["ignore","ignore","pipe"]});
 let launchDiagnostics="";proc.stderr.on("data",b=>{if(launchDiagnostics.length<8192)launchDiagnostics+=b.toString("utf8").slice(0,8192-launchDiagnostics.length);});
 let launchError;proc.on("error",e=>{launchError=e;});
 let ws,seq=0;const pending=new Map();
 try{
  const port=await until(async()=>{if(launchError||proc.exitCode!==null)throw Error("CI browser failed to start");try{return (await readFile(join(profile,"DevToolsActivePort"),"utf8")).split("\n")[0];}catch{return null;}},"debug port",45000);
  launchDiagnostics="";
  const page=await until(async()=>{try{return (await (await fetch("http://127.0.0.1:"+port+"/json/list")).json()).find(x=>x.type==="page");}catch{return null;}},"page");
  assert.match(page.webSocketDebuggerUrl,/^ws:\/\/127\.0\.0\.1:\d+\/devtools\/page\//);
  ws=new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve,reject)=>{ws.addEventListener("open",resolve,{once:true});ws.addEventListener("error",()=>reject(Error("CI browser socket unavailable")),{once:true});});
  ws.addEventListener("message",event=>{const x=JSON.parse(event.data),p=pending.get(x.id);if(p){pending.delete(x.id);clearTimeout(p.timer);x.error?p.reject(Error("Browser protocol command failed: "+p.method)):p.resolve(x.result);}});
  const c=(method,params={})=>new Promise((resolve,reject)=>{const id=++seq,timer=setTimeout(()=>{pending.delete(id);reject(Error("Browser protocol timeout: "+method));},10000);pending.set(id,{resolve,reject,timer,method});ws.send(JSON.stringify({id,method,params}));});
  const evaluate=async expression=>{const x=await c("Runtime.evaluate",{expression,returnByValue:true,awaitPromise:true});if(x.exceptionDetails)throw Error("Browser page evaluation failed");return x.result?.value;};
  await c("Page.enable");await c("Runtime.enable");await c("Page.setDownloadBehavior",{behavior:"allow",downloadPath:downloads});
  await c("Emulation.setDeviceMetricsOverride",{width:390,height:844,deviceScaleFactor:3,mobile:true});
  await c("Page.navigate",{url:base+"/candidate/workspace/"});
  await until(()=>evaluate("document.readyState==='complete' && !!document.getElementById('tenant')"),"workspace load");
  await evaluate("document.getElementById('tenant').value="+JSON.stringify(tenant)+";document.getElementById('token').value="+JSON.stringify(token)+";document.querySelector('[data-action=connect]').click()");
  await until(()=>evaluate("!document.getElementById('workspace').hidden && !document.querySelector('[data-action=connect]').disabled"),"authenticated workspace");
  await evaluate("document.querySelector('[data-tab=reports]').click(); document.getElementById('report-id').value="+JSON.stringify(run)+";document.querySelector('[data-action=report-read]').click()");
  await until(()=>evaluate("!document.querySelector('[data-action=report-read]').disabled && document.getElementById('report-result').textContent.includes("+JSON.stringify(traceDigest)+")"),"real report source receipt");
  assert.equal(await evaluate("document.documentElement.scrollWidth<=window.innerWidth"),true,"no document-level mobile overflow");
  assert.equal(await evaluate("document.getElementById('report-downloads').children.length"),0);
  await evaluate("document.querySelector('[data-action=report-export]').click()");
  await until(()=>evaluate("!document.querySelector('[data-action=report-export]').disabled && document.getElementById('status').textContent.includes('Explicit confirmation')"),"explicit export confirmation");
  assert.equal(await evaluate("document.getElementById('report-downloads').children.length"),0);
  await evaluate("document.getElementById('report-confirm').checked=true;document.querySelector('[data-action=report-export]').click()");
  await until(()=>evaluate("document.getElementById('report-downloads').children.length===2"),"audited download links");
  const names=await evaluate("Array.from(document.querySelectorAll('#report-downloads a')).map(a=>a.download)");
  assert.deepEqual(names,["profitpilot-management-"+run+".json","profitpilot-management-"+run+".txt"]);
  // Trigger the actual browser download with a trusted keyboard event.
  for(let i=0;i<2;i++){
   await evaluate("document.querySelectorAll('#report-downloads a')["+i+"].focus()");
   await c("Input.dispatchKeyEvent",{type:"keyDown",key:"Enter",code:"Enter",windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});
   await c("Input.dispatchKeyEvent",{type:"keyUp",key:"Enter",code:"Enter",windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});
   await until(async()=>{const list=await readdir(downloads);return list.includes(names[i]);},"downloaded file");
  }
  const data=JSON.parse(await readFile(join(downloads,names[0]),"utf8")),readable=await readFile(join(downloads,names[1]),"utf8");
  assert.equal(data.calculationId,run);assert.equal(data.sourceTrace.digest,traceDigest);assert.equal(data.indicativeContribution,"0.20");assert.equal(data.contribution,null);
  assert.match(readable,/Indicative contribution: AUD 0\.20/);
  assert.ok(!JSON.stringify(data).includes(token)&&!readable.includes(token));
  const urls=await evaluate("Array.from(document.querySelectorAll('#report-downloads a')).map(a=>a.href)");
  await evaluate("document.querySelector('[data-action=clear]').click()");
  assert.equal(await evaluate("document.getElementById('workspace').hidden && document.getElementById('token').value==='' && document.getElementById('report-downloads').children.length===0"),true);
  for(const url of urls)assert.equal(await evaluate("fetch("+JSON.stringify(url)+").then(()=>false,()=>true)"),true);
  console.log("Real headless Chromium, 390px mobile viewport: authenticated report read, explicit export confirmation, actual JSON/text downloads, source receipt and session cleanup passed");
 }catch(e){if(!ws&&launchDiagnostics)console.error("Chromium startup diagnostic categories:",{sandbox:/sandbox/i.test(launchDiagnostics),display:/display/i.test(launchDiagnostics),memory:/memory|resource temporarily unavailable/i.test(launchDiagnostics),devtools:/devtools/i.test(launchDiagnostics)});throw e;}finally{
  if(ws)ws.close();for(const p of pending.values())clearTimeout(p.timer);
  if(proc.exitCode===null&&!launchError){proc.kill("SIGTERM");await Promise.race([new Promise(r=>proc.once("exit",r)),sleep(2000)]);if(proc.exitCode===null)proc.kill("SIGKILL");}
  await rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:200});
 }
}
