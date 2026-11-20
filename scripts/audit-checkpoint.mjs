#!/usr/bin/env node
// Operator-only export and verification. Never copy keys/DB credentials into Git.
import pg from "pg";
import {readFileSync,openSync,fstatSync,readSync,closeSync,writeFileSync,constants} from "node:fs";
import {resolve} from "node:path";
import {pathToFileURL} from "node:url";
import {createHash,createPublicKey} from "node:crypto";
import {buildAuditManifest,loadAuditRows,signAuditManifest,verifyAuditCheckpoint,assertCheckpointMatchesRows} from "../src/audit-evidence.js";
function privateFile(path){
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const stat=fstatSync(fd);
  if(!stat.isFile()||(stat.mode&0o077)!==0||stat.size<1||stat.size>16384)throw Error("Private file must be a small owner-only regular file");
  const bytes=Buffer.alloc(stat.size),n=readSync(fd,bytes,0,bytes.length,0);
  if(n!==bytes.length)throw Error("Private file could not be read completely");
  return bytes.toString("utf8").trim();
 }finally{closeSync(fd);}
}
async function withReadOnlySnapshot(dbFile,operation){
 const connectionString=privateFile(dbFile);
 const url=new URL(connectionString);
 if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||!url.pathname||url.pathname==="/"||url.search||url.hash)
  throw Error("Invalid audit database connection configuration");
 const localTest=process.env.NODE_ENV==="test"&&["127.0.0.1","localhost","[::1]"].includes(url.hostname);
 const client=new pg.Client({connectionString,ssl:localTest?false:{rejectUnauthorized:true},connectionTimeoutMillis:5000});
 await client.connect();
 try{
  await client.query("BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY");
  await client.query("SET LOCAL statement_timeout='30000ms'");
  const result=await operation(client);
  await client.query("ROLLBACK");
  return result;
 }catch(e){try{await client.query("ROLLBACK")}catch{}throw e;}
 finally{await client.end();}
}
async function main(argv){
 const [command,...args]=argv;
 if(command==="verify"&&args.length===2){
  verifyAuditCheckpoint(JSON.parse(readFileSync(args[0],"utf8")),readFileSync(args[1],"utf8"));
  process.stdout.write("Signature and checkpoint structure verified; database comparison NOT performed\n");return;
 }
 if(command==="seal"&&(args.length===4||args.length===5)){
  const [tenantId,dbFile,keyFile,output,previous]=args;
  const pem=privateFile(keyFile);
  // Previous artifact is a chain link, not proof of independent witness custody.
  const previousCheckpointDigest=previous?createHash("sha256").update(readFileSync(previous)).digest("hex"):null;
  const manifest=await withReadOnlySnapshot(dbFile,async c=>
   buildAuditManifest(tenantId,await loadAuditRows(c,tenantId),{previousCheckpointDigest}));
  const bundle=signAuditManifest(manifest,pem);
  verifyAuditCheckpoint(bundle,createPublicKey(pem));
  writeFileSync(output,JSON.stringify(bundle,null,2)+"\n",{mode:0o600,flag:"wx"});
  process.stdout.write("Audit checkpoint sealed: "+manifest.count+" hashed events (external custody still required)\n");return;
 }
 if(command==="compare"&&args.length===3){
  const [checkpoint,pubkey,dbFile]=args;
  const bundle=JSON.parse(readFileSync(checkpoint,"utf8"));
  const pem=readFileSync(pubkey,"utf8");
  const manifest=verifyAuditCheckpoint(bundle,pem);
  const last=manifest.entries.at(-1);
  const rows=await withReadOnlySnapshot(dbFile,c=>loadAuditRows(c,manifest.tenantId,last??null));
  assertCheckpointMatchesRows(bundle,pem,rows);
  process.stdout.write("Current database historical prefix matches signed checkpoint\n");return;
 }
 throw Error("Usage: seal TENANT_UUID DB_URL_FILE PRIVATE_KEY_FILE NEW_OUTPUT [PREVIOUS_CHECKPOINT] | verify CHECKPOINT PUBLIC_KEY_FILE | compare CHECKPOINT PUBLIC_KEY_FILE DB_URL_FILE");
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 main(process.argv.slice(2)).catch(error=>{process.stderr.write("Audit checkpoint refused: "+error.message+"\n");process.exitCode=1;});
}
