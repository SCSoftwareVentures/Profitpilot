import {createServer} from "node:https";
import {readFileSync} from "node:fs";
import {timingSafeEqual} from "node:crypto";
import {pathToFileURL} from "node:url";
import pg from "pg";
import {requestBoundaryStatus} from "../server/network-boundary.js";
import {securityReaderConfig,readSecuritySnapshot,parseSecurityPage} from "./security-command-centre.js";
const TOKEN=/^[a-f0-9]{64}$/;
const HEADERS={"Cache-Control":"no-store","Pragma":"no-cache","X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Content-Security-Policy":"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'","Strict-Transport-Security":"max-age=31536000"};
const files=new Map([["/","security-dashboard.html"],["/dashboard.js","security-dashboard.js"],["/dashboard.css","security-dashboard.css"]].map(([path,file])=>[path,readFileSync(new URL("../ops/"+file,import.meta.url))]));
const secretEqual=(a,b)=>typeof a==="string"&&a.length===64&&TOKEN.test(a)&&timingSafeEqual(Buffer.from(a,"hex"),Buffer.from(b,"hex"));
export function dashboardHandler({token,authority,snapshot,clock=Date.now}){
 if(!TOKEN.test(token)||!/^localhost:[1-9]\d{0,4}$/.test(authority)||typeof snapshot!=="function")throw Error("Invalid dashboard configuration");
 let active=0,windowStart=0,requests=0;
 return async(req,res)=>{
  for(const [k,v] of Object.entries(HEADERS))res.setHeader(k,v);
  const send=(status,value,type="application/json; charset=utf-8")=>{res.statusCode=status;res.setHeader("Content-Type",type);res.end(value);};
  const fail=(status)=>send(status,JSON.stringify({error:"Dashboard request denied or unavailable"}));
  if(requestBoundaryStatus(req)!==0)return fail(400);
  if(req.headers.host!==authority||req.headers.origin&&req.headers.origin!=="https://"+authority||req.headers["sec-fetch-site"]==="cross-site"||req.method!=="GET"||
  req.headers["transfer-encoding"]||req.headers["content-length"]&&req.headers["content-length"]!=="0"||typeof req.url!=="string"||req.url.length>256)return fail(403);
  if(files.has(req.url))return send(200,files.get(req.url),req.url==="/"?"text/html; charset=utf-8":req.url.endsWith(".js")?"text/javascript; charset=utf-8":"text/css; charset=utf-8");
  if(!req.url.startsWith("/snapshot?")&&req.url!=="/snapshot")return fail(404);
  const now=clock();if(now-windowStart>=60000||now<windowStart){windowStart=now;requests=0;}
  if(++requests>60||active>=2){res.setHeader("Retry-After","10");return fail(429);}
  // Never place secrets in URLs, cookies, persistent browser storage or logs.
  if(!secretEqual(req.headers.authorization?.replace(/^Bearer /,""),token)||!req.headers.authorization?.startsWith("Bearer "))return fail(401);
  let page;
  try{
   const url=new URL(req.url,"https://"+authority),keys=[...url.searchParams.keys()];
   if(keys.some(k=>!["limit","cursor"].includes(k))||new Set(keys).size!==keys.length)throw Error("Invalid page");
   page=parseSecurityPage([url.searchParams.get("limit")??"50",...(url.searchParams.has("cursor")?[url.searchParams.get("cursor")]:[])]);
  }catch{return fail(400);}
  active++;
  try{const report=await snapshot(page);return send(report.catalogVerified?200:503,JSON.stringify(report));}
  catch{return fail(503);}finally{active--;}
 };
}
export async function checkedSecuritySnapshot(pool,page){
 const c=await pool.connect();
 try{
  const role=(await c.query("SELECT session_user AS login,current_user AS runtime,coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false) AS tls")).rows[0];
  if(role?.login!=="profitpilot_security_reader"||role.runtime!=="profitpilot_security_reader"||role.tls!==true)throw Error("Unexpected reader authority");
  return await readSecuritySnapshot(c,page);
 }finally{c.release();}
}
async function main(){
 const env=process.env,port=Number(env.SECURITY_DASHBOARD_PORT||8443),token=env.SECURITY_DASHBOARD_TOKEN;
 if(!Number.isInteger(port)||port<1024||port>65535||!TOKEN.test(token||"")||new Set(token).size<12)throw Error("Invalid dashboard boundary");
 const pool=new pg.Pool(securityReaderConfig(env));
 try{
  await checkedSecuritySnapshot(pool,{limit:1,cursor:null});
  const server=createServer({key:readFileSync(env.SECURITY_DASHBOARD_TLS_KEY_FILE),cert:readFileSync(env.SECURITY_DASHBOARD_TLS_CERT_FILE),minVersion:"TLSv1.2",maxHeaderSize:8192},dashboardHandler({token,authority:"localhost:"+port,snapshot:page=>checkedSecuritySnapshot(pool,page)}));
  server.maxHeadersCount=0;server.requestTimeout=8000;server.headersTimeout=5000;server.keepAliveTimeout=2000;server.maxConnections=16;
  server.on("checkContinue",(_req,res)=>{res.writeHead(417,{"Connection":"close","Cache-Control":"no-store"});res.end();});
  server.on("checkExpectation",(_req,res)=>{res.writeHead(417,{"Connection":"close","Cache-Control":"no-store"});res.end();});
  server.on("connect",(_req,socket)=>socket.destroy());server.on("upgrade",(_req,socket)=>socket.destroy());
  server.on("error",()=>{process.stderr.write("Security dashboard unavailable.\n");process.exitCode=1;void pool.end();});
  server.listen(port,"127.0.0.1",()=>process.stdout.write("Security dashboard listening on approved local TLS boundary.\n"));
  for(const sig of ["SIGINT","SIGTERM"])process.once(sig,()=>server.close(()=>void pool.end()));
 }catch(e){await pool.end();throw e;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{process.stderr.write("Security dashboard startup failed; details suppressed.\n");process.exitCode=1;});
