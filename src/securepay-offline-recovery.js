// S11.2: read-only cryptographic restoration rehearsal for synthetic evidence.
// Never mount this module on HTTP routes or return decrypted original bytes.
import {createHash} from "node:crypto";
import {resolveCustodyReceiptKey,decryptCustodyBytes,verifyScanMac} from "./securepay-encrypted-custody.js";

const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(x);
const hex64=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const sha=bytes=>createHash("sha256").update(bytes).digest("hex");
const forbiddenTrue=["origin_verified","source_identity_verified","independent_scanner_verified",
 "independent_custody_verified","retention_policy_enforced","decision_authority","payment_authority"];
const encodedRecord=x=>JSON.stringify([
 "ProfitPilot/S11.2/offline-restored-evidence/v1",x.tenantId,x.caseId,x.evidenceId,
 x.receiptId,x.keyId,x.sha256,x.byteCount,x.ciphertextSha256
]);

export function verifyRestoredCustodyRow(row,ring,expectedTenantId){
 if(!row||!uuid(expectedTenantId)||row.tenant_id!==expectedTenantId||
  ![row.id,row.case_id,row.evidence_id,row.client_request_id,row.received_by].every(uuid)||
  !hex64(row.sha256)||!hex64(row.aad_sha256)||!hex64(row.ciphertext_sha256)||
  !hex64(row.scanner_attestation_mac)||!Number.isInteger(row.byte_count)||
  row.byte_count<1||row.byte_count>524288||
  !["text/plain","application/pdf","image/png","image/jpeg"].includes(row.media_type)||
  row.scan_status!=="scanner_reported_clean"||row.encryption_algorithm!=="aes-256-gcm"||
  row.case_synthetic!==true||row.case_funds_moved!==false||
  row.evidence_externally_verified!==false||
  forbiddenTrue.some(field=>row[field]!==false)||
  !(row.ciphertext instanceof Buffer)||row.ciphertext.length!==row.byte_count||
  !(row.nonce instanceof Buffer)||row.nonce.length!==12||
  !(row.auth_tag instanceof Buffer)||row.auth_tag.length!==16)
  throw new Error("Synthetic restored receipt boundary or integrity invalid");
 const keys=resolveCustodyReceiptKey(ring,row.key_id);
 if(!keys)throw new Error("Historical custody key unavailable");
 let macOk=false;
 try{macOk=verifyScanMac(row,keys);}catch{}
 if(!macOk)throw new Error("Operator-origin scanner MAC invalid");
 const context={tenantId:row.tenant_id,caseId:row.case_id,evidenceId:row.evidence_id,
  clientRequestId:row.client_request_id,actorId:row.received_by,sha256:row.sha256,
  byteCount:row.byte_count,mediaType:row.media_type,keyId:row.key_id};
 const sealed={ciphertext:row.ciphertext,nonce:row.nonce,tag:row.auth_tag,
  aadSha256:row.aad_sha256,ciphertextSha256:row.ciphertext_sha256};
 const plaintext=decryptCustodyBytes(sealed,context,keys);
 try{
  // Only digest/size evidence is returned. Decrypted bytes never leave this call.
  if(plaintext.length!==row.byte_count||sha(plaintext)!==row.sha256)
   throw new Error("Recovered bytes mismatch");
  return {tenantId:row.tenant_id,caseId:row.case_id,evidenceId:row.evidence_id,
   receiptId:row.id,keyId:row.key_id,sha256:row.sha256,
   byteCount:row.byte_count,ciphertextSha256:row.ciphertext_sha256};
 }finally{plaintext.fill(0);}
}

export function summarizeRestoredCustodyRows(rows,ring,tenantId){
 if(!Array.isArray(rows)||rows.length<1||rows.length>64||!uuid(tenantId))
  throw new Error("Nonempty, bounded synthetic restored evidence set required");
 const checked=rows.map(row=>verifyRestoredCustodyRow(row,ring,tenantId));
 checked.sort((a,b)=>a.receiptId.localeCompare(b.receiptId));
 if(new Set(checked.map(x=>x.receiptId)).size!==checked.length||
  new Set(checked.map(x=>x.evidenceId)).size!==checked.length)
  throw new Error("Duplicate restored evidence receipt");
 const aggregateSha256=sha(Buffer.from(JSON.stringify([
  "ProfitPilot/S11.2/offline-restore-manifest/v1",tenantId,
  checked.map(encodedRecord)
 ]),"utf8"));
 return {schema:"profitpilot.s11.2.synthetic.restore.v1",tenantId,
  receivedEncryptedCount:checked.length,verifiedCount:checked.length,
  aggregateSha256,plaintextExposed:false,operatorScanIndependent:false,
  storageOriginIndependent:false,legalRetentionVerified:false,
  paymentAuthority:false,decisionAuthority:false};
}
