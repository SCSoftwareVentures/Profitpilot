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
export function createBoundedServer(app){
 const server=createServer({requestTimeout:15000,headersTimeout:10000,keepAliveTimeout:5000,connectionsCheckingInterval:1000,maxHeaderSize:16384},app);
 server.maxHeadersCount=64;
 server.maxRequestsPerSocket=100;
 server.maxConnections=256;
 server.setTimeout(20000,socket=>socket.destroy());
 return server;
}
