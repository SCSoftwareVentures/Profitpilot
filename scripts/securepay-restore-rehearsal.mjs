#!/usr/bin/env node
// Offline, privileged, READ-ONLY restored-DB recovery REHEARSAL.
// No HTTP endpoint, byte export, external destination or production approval.
import pg from "pg";
import {createHash,randomUUID} from "node:crypto";
import {openSync,fstatSync,readSync,closeSync,lstatSync,writeFileSync,constants} from "node:fs";
import {join,resolve} from "node:path";
import {pathToFileURL} from "node:url";
import {custodyKeyringSettings} from "../src/securepay-encrypted-custody.js";
import {summarizeRestoredCustodyRows} from "../src/securepay-offline-recovery.js";

const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(x);
const ticket=x=>typeof x==="string"&&/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,79}$/.test(x);
const sha=x=>createHash("sha256").update(x).digest("hex");

function privateSecretFile(path){
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const info=fstatSync(fd);
  if(!info.isFile()||info.size<1||info.size>4096||(info.mode&0o077)!==0)
   throw new Error("DB connection secret requires a private regular file");
  const bytes=Buffer.alloc(info.size);
  const n=readSync(fd,bytes,0,info.size,0);
  if(n!==info.size)throw new Error("Incomplete DB connection secret");
  return new TextDecoder("utf-8",{fatal:true}).decode(bytes).trim();
 }finally{closeSync(fd);}
}
function privateAuditDirectory(path){
 const s=lstatSync(path);
 if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)!==0)
  throw new Error("Audit directory must already exist with private owner-only access");
}
function writeAttempt(auditDir,attempt){
 privateAuditDirectory(auditDir);
 const bytes=JSON.stringify(attempt,null,2)+"\n";
 const file=join(auditDir,"s11-2-"+attempt.rehearsalId+".json");
 // Exclusive creation; no API or shared upload route can access this file.
 writeFileSync(file,bytes,{encoding:"utf8",mode:0o600,flag:"wx"});
 return {file,hash:sha(bytes)};
}
async function cryptographicRehearsal(tenantId,dbFile){
 const connectionString=privateSecretFile(dbFile);
 let url;
 try{url=new URL(connectionString);}catch{throw Error("Invalid restored database URL");}
 if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||
  !/^\/[a-zA-Z0-9_]+_restore$/.test(url.pathname)||url.search||url.hash)
  throw new Error("Only explicitly named offline restore databases are permitted");
 // Never access a live production database through this command.
 const loopback=["127.0.0.1","localhost","[::1]"].includes(url.hostname);
 if(!loopback)throw new Error("Offline restore must be reachable on loopback only");
 const ring=custodyKeyringSettings(process.env);
 if(ring.mode!=="mounted-keyring")throw new Error("Offline restore requires a separately mounted keyring");
 const client=new pg.Client({connectionString,ssl:process.env.NODE_ENV==="test"?false:{rejectUnauthorized:true},
  connectionTimeoutMillis:5000,query_timeout:30000});
 await client.connect();
 try{
  await client.query("BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY");
  await client.query("SET LOCAL statement_timeout = '30000ms'");
  const rows=await client.query(
   "SELECT r.*,k.synthetic AS case_synthetic,k.funds_moved AS case_funds_moved,"+
   "e.externally_verified AS evidence_externally_verified "+
   "FROM securepay_encrypted_custody_receipts r "+
   "JOIN securepay_case_rehearsals k ON k.tenant_id=r.tenant_id AND k.id=r.case_id "+
   "JOIN securepay_evidence_rehearsals e ON e.tenant_id=r.tenant_id AND e.case_id=r.case_id AND e.id=r.evidence_id "+
   "WHERE r.tenant_id=$1 ORDER BY r.id LIMIT 65",[tenantId]);
  const receipt=summarizeRestoredCustodyRows(rows.rows,ring,tenantId);
  await client.query("ROLLBACK");
  return receipt;
 }catch(error){try{await client.query("ROLLBACK");}catch{}throw error;}
 finally{await client.end();}
}

export async function runSyntheticRehearsal(argv,env=process.env){
 const [command,tenantId,dbFile,auditDir,operatorId,ticketRef]=argv;
 if(command!=="rehearse"||argv.length!==6||!uuid(tenantId)||!uuid(operatorId)||!ticket(ticketRef))
  throw Error("Usage: rehearse TENANT_UUID RESTORED_DB_URL_FILE PRIVATE_AUDIT_DIR OPERATOR_UUID TICKET_REF");
 if(env.NODE_ENV==="production"||env.PROFITPILOT_PROFILE!=="prototype"||
  env.SECUREPAY_OFFLINE_RECOVERY_MODE!=="synthetic-rehearsal")
  throw Error("Explicit synthetic-only offline rehearsal mode required");
 privateAuditDirectory(auditDir);
 const event={schema:"profitpilot.s11.2.restore-audit.v1",rehearsalId:randomUUID(),
  recordedAt:new Date().toISOString(),tenantId,operatorReportedId:operatorId,
  operatorReportedTicket:ticketRef,operatorIdentityIndependentlyVerified:false,
  externallyWitnessed:false,primaryDbMutated:false,plaintextExported:false,
  outcome:"rejected"};
 let failure;
 try{
  // No exception detail reaches stdout/audit: DB URLs or server error strings may contain secrets.
  const verified=await cryptographicRehearsal(tenantId,dbFile);
  event.outcome="verified_synthetic_recovery";
  event.recovery=verified;
 }catch(e){failure=e;event.reason="offline_rehearsal_denied";}
 const written=writeAttempt(auditDir,event);
 if(failure)throw Error("Offline synthetic recovery rejected; audit receipt "+event.rehearsalId);
 return {rehearsalId:event.rehearsalId,auditSha256:written.hash,
  verifiedEncryptedCount:event.recovery.verifiedCount};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 runSyntheticRehearsal(process.argv.slice(2)).then(x=>{
  process.stdout.write("Synthetic offline custody verified: "+x.verifiedEncryptedCount+
   " records; private audit ID "+x.rehearsalId+"; SHA-256 "+x.auditSha256+"\n");
 }).catch(()=>{
  process.stderr.write("Offline custody rehearsal refused; inspect restricted audit area if an attempt was recorded\n");
  process.exitCode=1;
 });
}
