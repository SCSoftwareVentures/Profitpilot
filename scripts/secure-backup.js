import {createCipheriv,createDecipheriv,randomBytes} from "node:crypto";
import {createReadStream,createWriteStream} from "node:fs";
import {appendFile,link,mkdtemp,open,rm,writeFile} from "node:fs/promises";
import {dirname,join,resolve} from "node:path";
import {pipeline} from "node:stream/promises";
import {spawn} from "node:child_process";
import {pathToFileURL} from "node:url";

const magic=Buffer.from("PPBACKUP1"), ivBytes=12, tagBytes=16, headerBytes=magic.length+ivBytes;
function keyFromHex(hex){
 if(typeof hex!=="string"||!/^[a-f0-9]{64}$/i.test(hex))throw new Error("Backup encryption requires a 32-byte hex key");
 return Buffer.from(hex,"hex");
}
async function publish(destination,work){
 const target=resolve(destination),tempDir=await mkdtemp(join(dirname(target),".pp-backup-")),temp=join(tempDir,"payload");
 try{
  await work(temp);
  const file=await open(temp,"r");
  try{await file.sync();}finally{await file.close();}
  // Atomic no-overwrite publication; existing paths (including symlinks) fail.
  await link(temp,target);
 }finally{await rm(tempDir,{recursive:true,force:true});}
}
export async function encryptBackup(input,destination,hex,producerDone=Promise.resolve()){
 const key=keyFromHex(hex);
 try{
  await publish(destination,async temp=>{
   const iv=randomBytes(ivBytes),header=Buffer.concat([magic,iv]);
   const cipher=createCipheriv("aes-256-gcm",key,iv,{authTagLength:tagBytes});
   cipher.setAAD(header);
   await writeFile(temp,header,{flag:"wx",mode:0o600});
   const outcomes=await Promise.allSettled([pipeline(input,cipher,createWriteStream(temp,{flags:"a"})),producerDone]);
   const failure=outcomes.find(x=>x.status==="rejected");
   if(failure)throw failure.reason;
   await appendFile(temp,cipher.getAuthTag());
  });
 }finally{key.fill(0);}
}
export async function decryptBackup(input,destination,hex){
 const key=keyFromHex(hex);
 let file;
 try{
  file=await open(input,"r");
  const stat=await file.stat();
  if(!stat.isFile()||stat.size<=headerBytes+tagBytes)throw new Error("Invalid backup file");
  const header=Buffer.alloc(headerBytes),tag=Buffer.alloc(tagBytes);
  if((await file.read(header,0,headerBytes,0)).bytesRead!==headerBytes||
     !header.subarray(0,magic.length).equals(magic)||
     (await file.read(tag,0,tagBytes,stat.size-tagBytes)).bytesRead!==tagBytes)
    throw new Error("Invalid backup envelope");
  const decipher=createDecipheriv("aes-256-gcm",key,header.subarray(magic.length),{authTagLength:tagBytes});
  decipher.setAAD(header);
  decipher.setAuthTag(tag);
  // Partial plaintext stays in a private temporary directory; publication
  // happens only after the GCM authentication tag verifies successfully.
  await publish(destination,temp=>pipeline(file.createReadStream({start:headerBytes,end:stat.size-tagBytes-1,autoClose:false}),decipher,createWriteStream(temp,{flags:"wx",mode:0o600})));
 }finally{key.fill(0);if(file)await file.close();}
}
async function dumpEncrypted(destination,key,env){
 if(!env.BACKUP_DATABASE_URL||!env.BACKUP_DATABASE_CA_FILE)throw new Error("Verified TLS backup connection required");
 const url=new URL(env.BACKUP_DATABASE_URL);
 if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||!url.username||!url.password||!url.pathname.slice(1)||url.search||url.hash)throw new Error("Invalid backup database URL");
 const user=decodeURIComponent(url.username);
 if(user==="profitpilot_app")throw new Error("Runtime database role cannot create a complete backup");
 keyFromHex(key).fill(0);
 const child=spawn("pg_dump",["--format=custom","--no-password"],{
  env:{PATH:env.PATH,PGHOST:url.hostname.replace(/^\[|\]$/g,""),PGPORT:url.port||"5432",PGDATABASE:decodeURIComponent(url.pathname.slice(1)),PGUSER:user,PGPASSWORD:decodeURIComponent(url.password),PGSSLMODE:"verify-full",PGSSLROOTCERT:env.BACKUP_DATABASE_CA_FILE,PGCONNECT_TIMEOUT:"5"},
  stdio:["ignore","pipe","ignore"]
 });
 const done=new Promise((resolve,reject)=>{
  child.once("error",reject);
  child.once("close",code=>code===0?resolve():reject(Error("Database dump failed")));
 });
 // Observe early spawn failures before starting asynchronous output preparation.
 void done.catch(()=>{});
 try{await encryptBackup(child.stdout,destination,key,done);}
 catch(e){child.kill();await done.catch(()=>{});throw e;}
}
async function main(){
 const [action,input,output]=process.argv.slice(2);
 const key=process.env.BACKUP_ENCRYPTION_KEY;
 if(action==="backup"&&input&&!output)await dumpEncrypted(input,key,process.env);
 else if(action==="encrypt-stdin"&&input&&!output)await encryptBackup(process.stdin,input,key);
 else if(action==="decrypt"&&input&&output)await decryptBackup(input,output,key);
 else throw new Error("Invalid backup command");
 process.stdout.write(JSON.stringify({event:"backup_tool_complete",action})+"\n");
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 main().catch(()=>{process.stderr.write("Backup operation failed; no secret, database error or file path logged.\n");process.exitCode=1;});
}
