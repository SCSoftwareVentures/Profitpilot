// Sandbox strict PNG subset: RGB/RGBA, 8-bit, non-interlaced, no metadata.
import {inflateSync} from "node:zlib";
import {spawn} from "node:child_process";
import {createHash} from "node:crypto";
import {signEnvelope,validKeyId} from "./key-envelope.mjs";
const signature=Buffer.from("89504e470d0a1a0a","hex");
export function crc32(bytes){
 let c=0xffffffff;
 for(const b of bytes){c^=b;for(let i=0;i<8;i++)c=(c>>>1)^((c&1)?0xedb88320:0);}
 return (c^0xffffffff)>>>0;
}
export function validEvidencePNG(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<57||bytes.length>2097152||!bytes.subarray(0,8).equals(signature))return false;
 try{
  let pos=8,w,h,bpp,ended=false,parts=[],total=0;
  while(pos+12<=bytes.length){
   const len=bytes.readUInt32BE(pos),next=pos+12+len;
   if(next>bytes.length||len>2097152)return false;
   const type=bytes.toString("ascii",pos+4,pos+8),data=bytes.subarray(pos+8,pos+8+len);
   if(crc32(bytes.subarray(pos+4,pos+8+len))!==bytes.readUInt32BE(pos+8+len))return false;
   if(type==="IHDR"){
    if(pos!==8||len!==13)return false;
    w=data.readUInt32BE(0);h=data.readUInt32BE(4);
    bpp=data[9]===2?3:data[9]===6?4:0;
    if(data[8]!==8||!bpp||!w||!h||w>4096||h>4096||w*h>4000000||data[10]||data[11]||data[12])return false;
   }else if(type==="IDAT"){
    if(!w||ended||parts.length>=256||!len)return false;
    total+=len;if(total>2097152)return false;parts.push(data);
   }else if(type==="IEND"){
    if(!parts.length||len||next!==bytes.length)return false;
    ended=true;pos=next;break;
   }else return false;
   pos=next;
  }
  if(!ended||pos!==bytes.length)return false;
  const row=w*bpp+1,expected=row*h;
  const compressed=Buffer.concat(parts),decoded=inflateSync(compressed,{maxOutputLength:expected,info:true});
  if(decoded.buffer.length!==expected||decoded.engine.bytesWritten!==compressed.length)return false;
  for(let y=0;y<h;y++)if(decoded.buffer[y*row]>4)return false;
  return true;
 }catch{return false;}
}
// Explicit opt-in only. Fixed executable, no shell, no filenames or output logs.
// ClamAV signature database and executable integrity must be provisioned separately.
export function clamavScanner({executable="/usr/bin/clamscan",timeoutMs=15000}={}){
 if(!executable.startsWith("/")||!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>30000)throw Error("Invalid scanner configuration");
 return bytes=>new Promise(resolve=>{
  let child,done=false,timer;
  const finish=result=>{if(done)return;done=true;clearTimeout(timer);resolve(result);};
  try{child=spawn(executable,["--no-summary","--stdout","-"],{stdio:["pipe","ignore","ignore"],shell:false});}
  catch{return finish("unavailable");}
  timer=setTimeout(()=>{child.kill("SIGKILL");finish("unavailable");},timeoutMs);
  child.on("error",()=>finish("unavailable"));
  child.on("close",code=>finish(code===0?"clean":code===1?"infected":"unavailable"));
  child.stdin.on("error",()=>finish("unavailable"));child.stdin.end(bytes);
 });
}
export function makeEvidenceScanner({key,keyId="primary",scan}){
 if(!Buffer.isBuffer(key)||key.length!==32||!validKeyId(keyId)||typeof scan!=="function")throw Error("Evidence scanner unavailable");
 return Object.freeze({async attest({photoId,tenantId,milestoneId,caseId,actorId,mediaType,content}){
  if(mediaType!=="image/png"||!validEvidencePNG(content))return null;
  const snapshot=Buffer.from(content);
  let result;try{result=await scan(snapshot);}catch{return null;}
  if(result!=="clean"||!snapshot.equals(content)||!validEvidencePNG(snapshot))return null;
  const digest=createHash("sha256").update(snapshot).digest("hex"),exp=Math.floor(Date.now()/1000)+30;
  return {digest,exp,signature:signEnvelope(key,keyId,["sp-evidence-scan-v1",photoId,tenantId,milestoneId,caseId,actorId,mediaType,digest,exp].join(":"))};
 }});
}
