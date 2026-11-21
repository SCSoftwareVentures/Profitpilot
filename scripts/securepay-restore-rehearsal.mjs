#!/usr/bin/env node
// Offline, privileged, READ-ONLY synthetic recovery rehearsal. No HTTP route or byte export.
import pg from "pg";
import {createHash,createPublicKey,randomUUID} from "node:crypto";
import {openSync,fstatSync,readSync,closeSync,lstatSync,readFileSync,
 readdirSync,writeFileSync,unlinkSync,constants} from "node:fs";
import {join,resolve} from "node:path";
import {pathToFileURL} from "node:url";
import {custodyKeyringSettings} from "../src/securepay-encrypted-custody.js";
import {summarizeRestoredCustodyRows} from "../src/securepay-offline-recovery.js";
import {loadRecoveryApproverPolicy,verifyRecoveryApproval,signRecoveryAudit,
 verifyRecoveryAudit} from "../src/securepay-recovery-controls.js";

const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(x);
const ticket=x=>typeof x==="string"&&/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,79}$/.test(x);
const sha=x=>createHash("sha256").update(x).digest("hex");
function privateFile(path,maxBytes=8192){
 if(typeof path!=="string"||!path)throw Error("Mounted private file required");
 const fd=openSync(path,constants.O_RDONLY|constants.O_NOFOLLOW|constants.O_NONBLOCK);
 try{
  const info=fstatSync(fd);
  if(!info.isFile()||info.size<1||info.size>maxBytes||(info.mode&0o077)!==0)
   throw Error("Mounted private file must be a bounded owner-only regular file");
  const bytes=Buffer.alloc(info.size),n=readSync(fd,bytes,0,info.size,0);
  if(n!==info.size)throw Error("Incomplete mounted private file");
  return new TextDecoder("utf-8",{fatal:true}).decode(bytes).trim();
 }finally{closeSync(fd);}
}
function privateAuditDirectory(path){
 const s=lstatSync(path);
 if(!s.isDirectory()||s.isSymbolicLink()||(s.mode&0o077)!==0)
  throw Error("Audit directory must already exist with private owner-only access");
}
function readAuditChain(auditDir,publicKey){
 const files=readdirSync(auditDir).filter(x=>x.startsWith("s11-3-"));
 if(files.length>256||files.some(x=>!/^s11-3-\d{6}\.json$/.test(x)))
  throw Error("Unrecognised or excessive signed audit records");
 files.sort();let previous=null;let firstTenant=null;const records=[];
 for(let i=0;i<files.length;i++){
  const name="s11-3-"+String(i+1).padStart(6,"0")+".json";
  if(files[i]!==name)throw Error("Signed audit continuity gap");
  const record=JSON.parse(privateFile(join(auditDir,name),16384));
  const digest=verifyRecoveryAudit(record,publicKey,previous);
  if(record.event.sequence!==i+1)throw Error("Invalid signed audit sequence");
  if(firstTenant!==null&&record.event.tenantId!==firstTenant)throw Error("Mixed tenant audit chain");
  firstTenant??=record.event.tenantId;
  records.push({event:record.event,digest});previous=digest;
 }
 return {previous,count:records.length,records};
}
function writeSignedAttempt(auditDir,prior,event,signerPrivate,signerPublic){
 privateAuditDirectory(auditDir);
 const bundle=signRecoveryAudit(event,prior.previous,signerPrivate);
 const digest=verifyRecoveryAudit(bundle,signerPublic,prior.previous);
 const file=join(auditDir,"s11-3-"+String(event.sequence).padStart(6,"0")+".json");
 const bytes=JSON.stringify(bundle,null,2)+"\n";
 if(Buffer.byteLength(bytes,"utf8")>16384)throw Error("Audit record too large");
 writeFileSync(file,bytes,{encoding:"utf8",mode:0o600,flag:"wx"});
 return {auditSha256:sha(bytes),signatureChainHead:digest};
}
async function cryptographicRehearsal(tenantId,dbFile,env){
 const connectionString=privateFile(dbFile,4096);
 let url;try{url=new URL(connectionString);}catch{throw Error("Invalid restored database URL");}
 if(!["postgres:","postgresql:"].includes(url.protocol)||!url.hostname||
  !/^\/[a-zA-Z0-9_]+_restore$/.test(url.pathname)||url.search||url.hash)
  throw Error("Only explicitly named offline restore databases are permitted");
 const loopback=["127.0.0.1","localhost","[::1]"].includes(url.hostname);
 if(!loopback)throw Error("Offline restore must be reachable on loopback only");
 const ring=custodyKeyringSettings(env);
 if(ring.mode!=="mounted-keyring")throw Error("Offline restore requires a separately mounted keyring");
 const client=new pg.Client({connectionString,ssl:env.NODE_ENV==="test"?false:{rejectUnauthorized:true},
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
 // A local lock serialises attempts; it is not a distributed lock or OS-level tamper protection.
 const lockFile=join(auditDir,".s11-3.lock");
 const lockFd=openSync(lockFile,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
 try{
  const signerPrivate=privateFile(env.SECUREPAY_RECOVERY_AUDIT_PRIVATE_KEY_FILE,4096);
  const signerPublic=privateFile(env.SECUREPAY_RECOVERY_AUDIT_PUBLIC_KEY_FILE,4096);
  const policy=loadRecoveryApproverPolicy(JSON.parse(privateFile(env.SECUREPAY_RECOVERY_APPROVERS_FILE)));
  const auditFingerprint=sha(createPublicKey(signerPublic).export({type:"spki",format:"der"}));
  for(const pinned of policy.values()){
   const approverFingerprint=sha(pinned.key.export({type:"spki",format:"der"}));
   if(approverFingerprint===auditFingerprint)
    throw Error("Recovery audit key must differ from both approval keys");
  }
  const prior=readAuditChain(auditDir,signerPublic);
  if(prior.count>=256)throw Error("Audit chain requires independent archival");
  if(prior.count>0&&prior.records[0].event.tenantId!==tenantId)throw Error("Audit directory tenant mismatch");
  const event={schema:"profitpilot.s11.3.restore-audit.v1",sequence:prior.count+1,
   recordedAt:new Date().toISOString(),tenantId,operatorReportedId:operatorId,
   operatorReportedTicket:ticketRef,approvalRequestId:null,approvalProofDigest:null,
   approvalKeyIds:[],legalHoldState:null,operatorIdentityIndependentlyVerified:false,
   approverIdentityIndependentlyVerified:false,externallyWitnessed:false,
   primaryDbMutated:false,plaintextExported:false,
   outcome:"rejected",reason:"offline_rehearsal_denied",recovery:null};
  // Verify the audit signer matches its independently supplied public key BEFORE
  // contacting the restored DB; a signing-key mismatch cannot cause unlogged decrypt.
  verifyRecoveryAudit(signRecoveryAudit(event,prior.previous,signerPrivate),signerPublic,prior.previous);
  let failure=null;
  try{
   const bundle=JSON.parse(privateFile(env.SECUREPAY_RECOVERY_APPROVAL_FILE));
   const approved=verifyRecoveryApproval(bundle,policy,{tenantId,operatorId,ticketRef});
   event.approvalRequestId=approved.requestId;
   event.approvalProofDigest=approved.proofDigest;
   event.approvalKeyIds=approved.signerIds;
   event.legalHoldState=approved.legalHoldState;
   if(prior.records.some(r=>r.event.approvalRequestId===approved.requestId))
    throw Error("Approval nonce was previously used");
   const verified=await cryptographicRehearsal(tenantId,dbFile,env);
   event.outcome="verified_synthetic_recovery";
   event.reason=null;event.recovery=verified;
  }catch(e){failure=e;}
  // Without a valid signed/append-only audit write, do not claim success.
  const audit=writeSignedAttempt(auditDir,prior,event,signerPrivate,signerPublic);
  if(failure)throw Error("Offline synthetic recovery rejected; signed audit sequence "+event.sequence);
  return {rehearsalId:event.approvalRequestId,auditSha256:audit.auditSha256,
   signedChainHead:audit.signatureChainHead,verifiedEncryptedCount:event.recovery.verifiedCount};
 }finally{
  closeSync(lockFd);
  // The OS owner can still tamper with this directory: external anchoring remains outstanding.
  unlinkSync(lockFile);
 }
}

// Verify an independently retained audit chain head, without DB or private keys.
// An externally preserved expected head is required to detect tail truncation.
export function runAuditVerification(argv){
 const [command,auditDir,publicKeyPath,expectedHead]=argv;
 if(command!=="verify-audit"||argv.length!==4||!/^[a-f0-9]{64}$/.test(expectedHead))
  throw Error("Usage: verify-audit PRIVATE_AUDIT_DIR PUBLIC_KEY_FILE PREVIOUSLY_RECORDED_HEAD_SHA256");
 privateAuditDirectory(auditDir);
 const chain=readAuditChain(auditDir,privateFile(publicKeyPath,4096));
 if(chain.count<1||chain.previous!==expectedHead)
  throw Error("Audit head differs from independently recorded checkpoint");
 return {verifiedSignedRecords:chain.count,head:chain.previous};
}
if(process.argv[1]&&import.meta.url===pathToFileURL(resolve(process.argv[1])).href){
 if(process.argv[2]==="verify-audit"){
  try{
   const result=runAuditVerification(process.argv.slice(2));
   process.stdout.write("Signed synthetic recovery audit checked: "+result.verifiedSignedRecords+
    " records; expected head verified\n");
  }catch{
   process.stderr.write("Signed recovery audit verification refused\n");process.exitCode=1;
  }
 }else runSyntheticRehearsal(process.argv.slice(2)).then(x=>{
  process.stdout.write("Synthetic offline custody verified: "+x.verifiedEncryptedCount+
   " records; signed audit SHA-256 "+x.auditSha256+"; chain head "+x.signedChainHead+"\n");
 }).catch(()=>{
  process.stderr.write("Offline custody rehearsal refused; consult restricted signed audit directory\n");
  process.exitCode=1;
 });
}
