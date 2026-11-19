// Sandbox strict PNG subset: RGB/RGBA, 8-bit, non-interlaced, no metadata.
import {inflateSync} from "node:zlib";
import {spawn} from "node:child_process";
import {fileURLToPath} from "node:url";
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
// Fixed decoder script and bounded subprocess. No caller-controlled file names.
// The service must additionally run in a restricted OS/container identity.
export function jpegNormalizer({executable="/usr/bin/python3",timeoutMs=8000}={}){
 if(!executable.startsWith("/")||!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>15000)throw Error("Invalid decoder configuration");
 const script=fileURLToPath(new URL("./normalize-evidence.py",import.meta.url));
 return bytes=>new Promise(resolve=>{
  if(!Buffer.isBuffer(bytes)||bytes.length>2097152)return resolve(null);
  let child,done=false,timer,total=0;const chunks=[];
  const finish=result=>{if(done)return;done=true;clearTimeout(timer);resolve(result);};
  try{child=spawn(executable,["-I",script],{stdio:["pipe","pipe","ignore"],shell:false});}
  catch{return finish(null);}
  timer=setTimeout(()=>{child.kill("SIGKILL");finish(null);},timeoutMs);
  child.on("error",()=>finish(null));
  child.stdout.on("data",b=>{total+=b.length;if(total>2097152){child.kill("SIGKILL");finish(null);}else if(!done)chunks.push(b);});
  child.on("close",code=>{if(done)return;const result=Buffer.concat(chunks);finish(code===0&&validEvidencePNG(result)?result:null);});
  child.stdin.on("error",()=>{child.kill("SIGKILL");finish(null);});child.stdin.end(bytes);
 });
}

export function makeEvidenceScanner({key,keyId="primary",scan,normalizeJPEG}){
 if(!Buffer.isBuffer(key)||key.length!==32||!validKeyId(keyId)||typeof scan!=="function")throw Error("Evidence scanner unavailable");
 return Object.freeze({async attest({photoId,tenantId,milestoneId,caseId,actorId,mediaType,content}){
  if(!Buffer.isBuffer(content)||content.length<8||content.length>2097152||!["image/png","image/jpeg"].includes(mediaType))return null;
  const original=Buffer.from(content),originalDigest=createHash("sha256").update(original).digest("hex");
  let result,normalized;
  try{
   result=await scan(Buffer.from(original));
   if(result!=="clean")return null;
   if(mediaType==="image/png"){if(!validEvidencePNG(original))return null;normalized=original;}
   else{
    if(typeof normalizeJPEG!=="function")return null;
    normalized=await normalizeJPEG(Buffer.from(original));
    if(!validEvidencePNG(normalized))return null;
    if(await scan(Buffer.from(normalized))!=="clean")return null;
   }
  }catch{return null;}
  const digest=createHash("sha256").update(normalized).digest("hex"),exp=Math.floor(Date.now()/1000)+30;
  return {digest,originalDigest,originalMediaType:mediaType,content:Buffer.from(normalized),exp,
   signature:signEnvelope(key,keyId,["sp-evidence-scan-v2",photoId,tenantId,milestoneId,caseId,actorId,"image/png",digest,mediaType,originalDigest,exp].join(":"))};
 }});
}
