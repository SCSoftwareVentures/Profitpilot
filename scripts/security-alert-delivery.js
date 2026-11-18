import {createHmac,randomUUID,timingSafeEqual} from "node:crypto";
import {request} from "node:https";
import {lstatSync,readFileSync,writeFileSync,renameSync,mkdirSync,rmdirSync,unlinkSync,existsSync} from "node:fs";
import {join} from "node:path";
import {pathToFileURL} from "node:url";
import pg from "pg";
import {securityReaderConfig} from "./security-command-centre.js";
import {checkedSecuritySnapshot} from "./security-dashboard.js";
const CATEGORIES=["snapshot_unavailable","catalog_drift","tenant_containment","actor_containment","scanner_backlog","promotion_backlog"];
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
const SECRET=/^[a-f0-9]{64}$/;
const exact=(v,keys)=>v!==null&&typeof v==="object"&&!Array.isArray(v)&&Object.keys(v).length===keys.length&&keys.every(k=>Object.hasOwn(v,k));
const validDate=s=>typeof s==="string"&&Number.isFinite(Date.parse(s))&&new Date(s).toISOString()===s;
export const initialAlertState=()=>({version:1,states:Object.fromEntries(CATEGORIES.map(k=>[k,false])),pending:[]});
function validateEvent(e){
 if(!exact(e,["id","category","state","observedAt"])||typeof e.id!=="string"||!UUID.test(e.id)||!CATEGORIES.includes(e.category)||!["active","cleared"].includes(e.state)||!validDate(e.observedAt))throw Error("Invalid alert event");
 return e;
}
function validateState(s){
 if(!exact(s,["version","states","pending"])||s.version!==1||!exact(s.states,CATEGORIES)||CATEGORIES.some(k=>typeof s.states[k]!=="boolean")||!Array.isArray(s.pending)||s.pending.length>32)throw Error("Invalid durable alert state");
 for(const e of s.pending)validateEvent(e);
 if(new Set(s.pending.map(e=>e.id)).size!==s.pending.length)throw Error("Duplicate pending alert");
 return s;
}
// No incident UUIDs, identity attributes, counts, URLs or raw logs leave
// the monitoring boundary. Unknown signals stay active until observed again.
export function observeAlerts(state,snapshot,now=new Date().toISOString()){
 validateState(state);if(!validDate(now))throw Error("Invalid observation timestamp");
 const next=structuredClone(state);
 const values={snapshot_unavailable:snapshot===null};
 if(snapshot!==null){
  values.catalog_drift=snapshot.catalogVerified!==true;
  if(snapshot.catalogVerified===true){
   values.tenant_containment=snapshot.counts.activeTenantIncidents>0;
   values.actor_containment=snapshot.counts.temporarilyContainedActors>=5;
   values.scanner_backlog=snapshot.counts.pendingOrRetryableScans>=10;
   values.promotion_backlog=snapshot.counts.pendingOrProcessingPromotions>=10;
  }
 }
 for(const k of CATEGORIES){
  if(!Object.hasOwn(values,k)||values[k]===next.states[k])continue;
  if(next.pending.length>=32)throw Error("Alert backlog full; operator intervention required");
  next.pending.push({id:randomUUID(),category:k,state:values[k]?"active":"cleared",observedAt:now});
  next.states[k]=values[k];
 }
 return next;
}
const mac=(body,timestamp,key)=>createHmac("sha256",Buffer.from(key,"hex")).update("profitpilot-alert-v1\n"+timestamp+"\n"+body).digest("hex");
export function signedAlert(event,key,now=Math.floor(Date.now()/1000)){
 validateEvent(event);if(!SECRET.test(key)||new Set(key).size<12||!Number.isSafeInteger(now)||now<=0)throw Error("Invalid alert signing configuration");
 const body=JSON.stringify({format:"profitpilot-alert-v1",...event}),timestamp=String(now);
 return {body,headers:{"Content-Type":"application/json","Content-Length":String(Buffer.byteLength(body)),"X-ProfitPilot-Timestamp":timestamp,"X-ProfitPilot-Signature":mac(body,timestamp,key),"Idempotency-Key":event.id}};
}
export function verifyAlert(body,headers,key,now=Math.floor(Date.now()/1000)){
 const ts=headers["X-ProfitPilot-Timestamp"]??headers["x-profitpilot-timestamp"],sig=headers["X-ProfitPilot-Signature"]??headers["x-profitpilot-signature"];
 if(typeof body!=="string"||Buffer.byteLength(body)>1024||!SECRET.test(key)||typeof ts!=="string"||!/^[1-9]\d{0,11}$/.test(ts)||Math.abs(now-Number(ts))>300||typeof sig!=="string"||!SECRET.test(sig)||!timingSafeEqual(Buffer.from(sig,"hex"),Buffer.from(mac(body,ts,key),"hex")))throw Error("Invalid alert signature or freshness");
 const parsed=JSON.parse(body);if(!exact(parsed,["format","id","category","state","observedAt"])||parsed.format!=="profitpilot-alert-v1")throw Error("Invalid alert payload");
 const {format,...event}=parsed;
 validateEvent(event);if((headers["Idempotency-Key"]??headers["idempotency-key"])!==event.id)throw Error("Invalid idempotency key");
 return event;
}
export function alertDestination(env=process.env){
 if(env.NODE_TLS_REJECT_UNAUTHORIZED==="0")throw Error("TLS verification required");
 const url=new URL(env.SECURITY_ALERT_WEBHOOK_URL||"");
 const key=env.SECURITY_ALERT_SIGNING_KEY;
 if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash||url.pathname==="/"||!SECRET.test(key||"")||new Set(key).size<12||env.SECURITY_ALERT_ENABLED!=="yes")throw Error("Explicit approved HTTPS destination required");
 return {url,key,ca:env.SECURITY_ALERT_CA||undefined};
}
export async function deliverAlert(event,{url,key,ca}){
 const {body,headers}=signedAlert(event,key);
 await new Promise((resolve,reject)=>{
  const req=request(url,{method:"POST",headers,ca,rejectUnauthorized:true,minVersion:"TLSv1.2",signal:AbortSignal.timeout(5000)},res=>{
   res.destroy();if(res.statusCode>=200&&res.statusCode<300)resolve();else reject(Error("Alert delivery not acknowledged"));
  });
  req.once("error",reject);req.end(body);
 });
}
function privateDirectory(dir){
 const s=lstatSync(dir);if(!s.isDirectory()||s.mode&0o077||typeof process.getuid==="function"&&s.uid!==process.getuid())throw Error("Private owned alert state directory required");
}
function privateState(path){
 if(!existsSync(path))return initialAlertState();
 const s=lstatSync(path);if(!s.isFile()||s.mode&0o077||s.size>65536||typeof process.getuid==="function"&&s.uid!==process.getuid())throw Error("Invalid alert state file");
 return validateState(JSON.parse(readFileSync(path,"utf8")));
}
function persist(dir,state){
 validateState(state);const temp=join(dir,"state-"+randomUUID()+".tmp");
 try{writeFileSync(temp,JSON.stringify(state)+"\n",{mode:0o600,flag:"wx",flush:true});renameSync(temp,join(dir,"state.json"));}
 finally{if(existsSync(temp))unlinkSync(temp);}
}
export async function runAlertCycle({dir,read,deliver}){
 privateDirectory(dir);const lock=join(dir,"cycle.lock");mkdirSync(lock,{mode:0o700});
 try{
  let state=privateState(join(dir,"state.json"));
  // Drain existing pending events first so network downtime cannot destroy
  // the queue or cause silent replacement of an undelivered transition.
  let sent=0;
  const drain=async()=>{
   while(state.pending.length&&sent<32){
    await deliver(state.pending[0]);state.pending.shift();persist(dir,state);sent++;
   }
  };
  let deliveryFailed=false;
  try{await drain();}catch{deliveryFailed=true;}
  let snapshot=null;
  try{snapshot=await read();}catch{}
  state=observeAlerts(state,snapshot);persist(dir,state);
  if(!deliveryFailed)try{await drain();}catch{deliveryFailed=true;}
  if(deliveryFailed||state.pending.length)throw Error("Pending security alert delivery; retry required");
  return {sent,remaining:state.pending.length};
 }finally{rmdirSync(lock);}
}
async function main(){
 const env=process.env,destination=alertDestination(env),pool=new pg.Pool(securityReaderConfig(env));
 try{
  const result=await runAlertCycle({dir:env.SECURITY_ALERT_STATE_DIR,read:()=>checkedSecuritySnapshot(pool,{limit:1,cursor:null}),deliver:e=>deliverAlert(e,destination)});
  process.stdout.write(JSON.stringify({event:"security_alert_cycle",...result})+"\n");
 }finally{await pool.end();}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{process.stderr.write("Security alert cycle failed; retry and investigate. Details suppressed.\n");process.exitCode=1;});
