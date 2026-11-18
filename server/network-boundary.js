import {createServer} from "node:http";
import {isIP} from "node:net";

function canonicalIp(ip){
 if(typeof ip!=="string"||!isIP(ip)||ip.includes("%"))return null;
 if(isIP(ip)===4)return ip;
 const normalized=new URL("http://["+ip+"]/").hostname.slice(1,-1);
 const mapped=/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(normalized);
 if(mapped){const a=parseInt(mapped[1],16),z=parseInt(mapped[2],16);return [a>>8,a&255,z>>8,z&255].join(".");}
 return normalized;
}
export function proxyTrust(env=process.env){
 const raw=(env.TRUSTED_PROXY_IPS||"").trim();
 if(!raw)return ()=>false;
 const list=raw.split(",").map(x=>canonicalIp(x.trim()));
 if(list.length>16||list.some(x=>!x||x==="0.0.0.0"||x==="::"))throw new Error("Trusted proxy configuration requires exact bounded IP addresses");
 const trusted=new Set(list);
 // Trust only the immediate, explicitly configured reverse proxy. Never trust
 // a proxy merely because it appears farther down a supplied forwarding chain.
 return (address,hop)=>hop===0&&trusted.has(canonicalIp(address));
}
export function corsOrigins(env=process.env){
 const values=(env.CORS_ORIGIN||"").split(",").map(x=>x.trim()).filter(Boolean);
 if(values.length>16)throw new Error("Too many CORS origins");
 for(const value of values){
  let url;try{url=new URL(value);}catch{throw new Error("Invalid CORS origin");}
  if(url.origin!==value||!["https:","http:"].includes(url.protocol)||(env.NODE_ENV==="production"&&url.protocol!=="https:"))throw new Error("CORS requires exact permitted origins");
 }
 return [...new Set(values)];
}
// Inspect raw headers before Node's normalized header map can discard
// duplicates or merge security-sensitive fields.
const uniqueHeaders=new Set(["host","authorization","proxy-authorization","content-length","transfer-encoding","content-type","content-encoding","expect","connection","upgrade","origin","forwarded","x-forwarded-for","x-forwarded-host","x-forwarded-proto","x-forwarded-port","x-real-ip","trailer","te"]);
export function requestBoundaryStatus(req){
 if(req.rawHeaders.length>128)return 431;
 const seen=new Set();
 for(let i=0;i<req.rawHeaders.length;i+=2){
  const name=req.rawHeaders[i].toLowerCase();
  if(uniqueHeaders.has(name)&&seen.has(name))return 400;
  seen.add(name);
 }
 if(req.httpVersion!=="1.1"&&req.httpVersion!=="1.0")return 400;
 if(req.httpVersion==="1.1"&&(!seen.has("host")||!req.headers.host?.trim()))return 400;
 if(req.headers.host&&/[\s,\/\\@?#]/.test(req.headers.host))return 400;
 if(!["GET","HEAD","POST","OPTIONS"].includes(req.method))return 405;
 if(typeof req.url!=="string"||req.url.length>4096)return 414;
 if(!req.url.startsWith("/")||req.url.startsWith("//")||/[\x00-\x20\x7f\\#]/.test(req.url))return 400;
 if(seen.has("expect"))return 417;
 if(seen.has("upgrade")||seen.has("trailer")||seen.has("te")||seen.has("proxy-authorization"))return 400;
 if(seen.has("transfer-encoding")&&(seen.has("content-length")||req.headers["transfer-encoding"].trim().toLowerCase()!=="chunked"||req.httpVersion!=="1.1"))return 400;
 if(seen.has("content-length")&&!/^(0|[1-9][0-9]{0,8})$/.test(req.headers["content-length"]))return 400;
 if(req.method!=="POST"&&(seen.has("transfer-encoding")||Number(req.headers["content-length"]||0)>0))return 400;
 if(Number(req.headers["content-length"]||0)>102400)return 413;
 return 0;
}
const rejectedSockets=new WeakSet();
function deny(res,status){
 rejectedSockets.add(res.socket);
 res.writeHead(status,{"Connection":"close","Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Content-Type":"application/json","Allow":"GET, HEAD, POST, OPTIONS"});
 res.end(JSON.stringify({error:"Request rejected at HTTP boundary"}));
}
export function createBoundedServer(app){
 const server=createServer({requestTimeout:15000,headersTimeout:10000,keepAliveTimeout:5000,connectionsCheckingInterval:1000,maxHeaderSize:16384,insecureHTTPParser:false},(req,res)=>{
  if(rejectedSockets.has(req.socket))return;
  const status=requestBoundaryStatus(req);
  if(status)return deny(res,status);
  app(req,res);
 });
 // Node truncates headers silently with a nonzero maxHeadersCount.
 // The byte limit bounds allocation; reject excess raw headers explicitly.
 server.maxHeadersCount=0;
 server.on("checkContinue",(_req,res)=>deny(res,417));
 server.on("checkExpectation",(_req,res)=>deny(res,417));
 server.on("upgrade",(_req,socket)=>socket.destroy());
 server.on("connect",(_req,socket)=>socket.destroy());
 server.maxRequestsPerSocket=100;
 server.maxConnections=256;
 server.setTimeout(20000,socket=>socket.destroy());
 return server;
}
