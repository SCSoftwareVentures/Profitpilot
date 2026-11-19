import {createConnection} from "node:net";
import {isAbsolute} from "node:path";
import {MAX_QUARANTINE_BYTES} from "./quarantine.js";

// ClamAV's local Unix-socket protocol. Bounded input, response and deadline;
// never log scanner results, which can include sensitive file information.
function exchange(path,request,timeoutMs=8000){
 if(typeof path!=="string"||!isAbsolute(path)||path.includes("\0"))return Promise.reject(new Error("Invalid scanner socket"));
 return new Promise((resolve,reject)=>{
  const socket=createConnection({path});
  const chunks=[];let n=0,settled=false;
  const finish=(error,value)=>{
   if(settled)return;settled=true;clearTimeout(timer);socket.destroy();
   if(error)reject(error);else resolve(value);
  };
  const timer=setTimeout(()=>finish(new Error("Scanner deadline exceeded")),timeoutMs);
  socket.on("connect",()=>socket.write(request));
  socket.on("error",()=>finish(new Error("Scanner unavailable")));
  socket.on("end",()=>finish(new Error("Incomplete scanner response")));
  socket.on("close",()=>finish(new Error("Scanner connection closed")));
  socket.on("data",chunk=>{
   n+=chunk.length;
   if(n>1024)return finish(new Error("Scanner response too large"));
   chunks.push(chunk);
   const data=Buffer.concat(chunks);
   const end=data.indexOf(0);
   if(end<0)return;
   if(end!==data.length-1)return finish(new Error("Unexpected scanner response"));
   finish(null,data.subarray(0,end).toString("utf8"));
  });
 });
}
export function signaturesFresh(version,now=Date.now()){
 // Daemon must use UTC. Refuse missing, stale or unexpectedly future definitions.
 const match=/^ClamAV [0-9]+\.[0-9]+\.[0-9]+[^/]*\/[0-9]+\/(.+)$/.exec(version);
 if(!match)return false;
 const date=Date.parse(match[1]+" UTC");
 return Number.isFinite(date)&&date<=now+300000&&now-date<=48*3600000;
}
export async function scanClamav(bytes,{socketPath,now=Date.now}={}){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>MAX_QUARANTINE_BYTES)throw new Error("Invalid scan input");
 const version=await exchange(socketPath,Buffer.from("zVERSION\0"));
 if(!signaturesFresh(version,now()))throw new Error("Scanner definitions are not current");
 const frame=Buffer.alloc(4);frame.writeUInt32BE(bytes.length);
 const request=Buffer.concat([Buffer.from("zINSTREAM\0"),frame,bytes,Buffer.alloc(4)]);
 try{
  const response=await exchange(socketPath,request);
  if(response==="stream: OK")return "clean";
  if(/^stream: [^\r\n\x00]{1,512} FOUND$/.test(response))return "infected";
  throw new Error("Scanner did not return a recognized verdict");
 }finally{request.fill(0);}
}
