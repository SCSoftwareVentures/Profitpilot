// Offline operator tool: authenticated encryption of bounded PostgreSQL custom-format dumps.
// No provider, credentials or storage service is required by the module or its tests.
import {createCipheriv,createDecipheriv,randomBytes} from "node:crypto";
import {open,unlink} from "node:fs/promises";
import {constants} from "node:fs";
import {pathToFileURL} from "node:url";

const magic=Buffer.from("PPB1");
const dumpMagic=Buffer.from("PGDMP");
const maxDump=128*1024*1024; // Fail closed; larger backups need a reviewed streaming format.
const maxMeta=4096;
const maxEnvelope=maxDump+maxMeta+4+12+16+4;
const identifier=/^[A-Za-z0-9._-]{3,128}$/;
const digest=/^[a-f0-9]{64}$/;
function keyBytes(key){
 if(typeof key!=="string"||!digest.test(key))throw Error("Independent 256-bit backup encryption key required");
 return Buffer.from(key,"hex");
}
function identity({deploymentId,backupId,checkpointSha256}={}){
 if(typeof deploymentId!=="string"||!identifier.test(deploymentId)||typeof backupId!=="string"||!identifier.test(backupId)||
 typeof checkpointSha256!=="string"||!digest.test(checkpointSha256))throw Error("Expected deployment, backup identity and independent checkpoint digest required");
 return {deploymentId,backupId,checkpointSha256};
}
function validateDump(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<dumpMagic.length||bytes.length>maxDump||!bytes.subarray(0,5).equals(dumpMagic))
  throw Error("Bounded PostgreSQL custom-format archive required");
}
export function sealDump(dump,{key,now=Date.now(),...ids}={}){
 validateDump(dump);
 const metadata={version:1,...identity(ids),createdAt:new Date(now).toISOString()};
 const meta=Buffer.from(JSON.stringify(metadata),"utf8");
 if(meta.length>maxMeta)throw Error("Backup metadata too large");
 const len=Buffer.alloc(4);len.writeUInt32BE(meta.length);
 const nonce=randomBytes(12),header=Buffer.concat([magic,nonce]);
 const secret=keyBytes(key);
 try{
  const cipher=createCipheriv("aes-256-gcm",secret,nonce,{authTagLength:16});
  cipher.setAAD(header);
  return Buffer.concat([header,cipher.update(len),cipher.update(meta),cipher.update(dump),cipher.final(),cipher.getAuthTag()]);
 }finally{secret.fill(0);}
}
export function openDump(envelope,{key,...ids}={}){
 const expected=identity(ids);
 if(!Buffer.isBuffer(envelope)||envelope.length<16+16+4+5||envelope.length>maxEnvelope||!envelope.subarray(0,4).equals(magic))
  throw Error("Invalid encrypted backup format");
 const header=envelope.subarray(0,16),nonce=header.subarray(4),tag=envelope.subarray(-16);
 const secret=keyBytes(key);
 let partial,plain;
 try{
  const cipher=createDecipheriv("aes-256-gcm",secret,nonce,{authTagLength:16});
  cipher.setAAD(header);cipher.setAuthTag(tag);
  partial=cipher.update(envelope.subarray(16,-16));
  plain=Buffer.concat([partial,cipher.final()]);
 }catch{
  throw Error("Encrypted backup authentication failed");
 }finally{
  secret.fill(0);partial?.fill(0);
 }
 try{
  if(plain.length<9)throw Error("Invalid authenticated backup content");
  const n=plain.readUInt32BE(0);
  if(n<2||n>maxMeta||4+n+5>plain.length)throw Error("Invalid authenticated backup metadata");
  const metadata=JSON.parse(plain.subarray(4,4+n).toString("utf8"));
  if(metadata.version!==1||!Number.isFinite(Date.parse(metadata.createdAt))||
   Object.keys(expected).some(k=>metadata[k]!==expected[k]))throw Error("Backup identity or checkpoint mismatch");
  const dump=Buffer.from(plain.subarray(4+n));
  try{validateDump(dump);return {metadata,dump};}catch(e){dump.fill(0);throw e;}
 }finally{plain.fill(0);}
}
async function readBounded(file,limit){
 const fd=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{
  const st=await fd.stat();
  if(!st.isFile()||st.size<1||st.size>limit)throw Error("Backup input must be a regular bounded file");
  const data=Buffer.alloc(st.size);let offset=0;
  while(offset<data.length){
   const result=await fd.read(data,offset,data.length-offset,offset);
   if(!result.bytesRead){data.fill(0);throw Error("Backup changed during read");}
   offset+=result.bytesRead;
  }
  if((await fd.read(Buffer.alloc(1),0,1,offset)).bytesRead||(await fd.stat()).size!==st.size){
   data.fill(0);throw Error("Backup changed during read");
  }
  return data;
 }finally{await fd.close();}
}
async function writeExclusive(file,bytes){
 const fd=await open(file,"wx",0o600);
 let success=false;
 try{await fd.writeFile(bytes);await fd.sync();success=true;}
 finally{try{await fd.close();}finally{if(!success)await unlink(file).catch(()=>{});}}
}
export async function sealFile(input,output,options){
 const dump=await readBounded(input,maxDump);
 try{await writeExclusive(output,sealDump(dump,options));}
 finally{dump.fill(0);}
}
export async function openFile(input,output,options){
 const envelope=await readBounded(input,maxEnvelope);
 // Authentication and identity checks finish before a plaintext file is created.
 const {metadata,dump}=openDump(envelope,options);
 try{await writeExclusive(output,dump);return metadata;}
 finally{dump.fill(0);}
}
async function main(){
 const [mode,input,output]=process.argv.slice(2);
 if(!input||!output||!["seal","open"].includes(mode))throw Error("Use seal|open <input> <output>");
 const key=process.env.PRIVACY_BACKUP_ENCRYPTION_KEY;
 if(!process.env.PRIVACY_CHECKPOINT_KEY||key===process.env.PRIVACY_CHECKPOINT_KEY)throw Error("Independent checkpoint and backup keys required");
 const options={key,deploymentId:process.env.PRIVACY_DEPLOYMENT_ID,backupId:process.env.PRIVACY_BACKUP_ID,checkpointSha256:process.env.PRIVACY_BACKUP_CHECKPOINT_SHA256};
 keyBytes(process.env.PRIVACY_CHECKPOINT_KEY).fill(0);
 if(mode==="seal")await sealFile(input,output,options);else await openFile(input,output,options);
 console.log("Backup "+(mode==="seal"?"encrypted":"authenticated and opened")+"; independent restore-state verification remains mandatory.");
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href)main().catch(()=>{console.error("Backup operation failed; no cutover is authorized.");process.exitCode=1;});
