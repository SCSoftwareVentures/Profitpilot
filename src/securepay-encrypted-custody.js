import {createCipheriv,createDecipheriv,createHash,createHmac,randomBytes,timingSafeEqual} from "node:crypto";
import {readSecret} from "../server/deployment.js";
const sha=bytes=>createHash("sha256").update(bytes).digest("hex");
const validId=x=>typeof x==="string"&&/^[a-zA-Z0-9][a-zA-Z0-9._:-]{2,63}$/.test(x);
const hex64=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
export function custodyKeySettings(env=process.env){
 const cipherKey=readSecret("SECUREPAY_CUSTODY_ENCRYPTION_KEY",env);
 const macKey=readSecret("SECUREPAY_CUSTODY_ATTESTATION_KEY",env);
 const keyId=env.SECUREPAY_CUSTODY_KEY_ID;
 if(!hex64(cipherKey)||!hex64(macKey)||cipherKey===macKey||!validId(keyId))
  throw new Error("Explicit independent custody encryption, attestation keys and key ID required");
 return {cipherKey:Buffer.from(cipherKey,"hex"),macKey:Buffer.from(macKey,"hex"),keyId};
}
export const custodyAad=context=>Buffer.from(JSON.stringify([
 "ProfitPilot/S10/custody-AAD/v1",context.tenantId,context.caseId,context.evidenceId,
 context.clientRequestId,context.actorId,context.sha256,context.byteCount,
 context.mediaType,"scanner_reported_clean",context.keyId
]),"utf8");
const scanPayload=(context,observedAt,cipherHash)=>JSON.stringify([
 "ProfitPilot/S10/operator-observed-scan/v1",context.tenantId,context.caseId,context.evidenceId,
 context.clientRequestId,context.actorId,context.sha256,context.byteCount,
 context.mediaType,"scanner_reported_clean",context.keyId,observedAt,cipherHash
]);
export function sealCustodyBytes(bytes,context,keys,observedAt=new Date().toISOString()){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>524288||!hex64(context.sha256)||
  sha(bytes)!==context.sha256||bytes.length!==context.byteCount||
  !keys||keys.cipherKey?.length!==32||keys.macKey?.length!==32||
  keys.keyId!==context.keyId||!Number.isFinite(Date.parse(observedAt)))
  throw new TypeError("Complete, matching original custody data and safe keys required");
 const aad=custodyAad(context);
 const nonce=randomBytes(12);
 const cipher=createCipheriv("aes-256-gcm",keys.cipherKey,nonce,{authTagLength:16});
 cipher.setAAD(aad);
 const ciphertext=Buffer.concat([cipher.update(bytes),cipher.final()]);
 const tag=cipher.getAuthTag(),ciphertextSha256=sha(ciphertext);
 const attestationMac=createHmac("sha256",keys.macKey)
  .update(scanPayload(context,observedAt,ciphertextSha256)).digest("hex");
 return {ciphertext,nonce,tag,aadSha256:sha(aad),ciphertextSha256,
  attestationMac,observedAt,keyId:keys.keyId,algorithm:"aes-256-gcm"};
}
export function decryptCustodyBytes(sealed,context,keys){
 if(!sealed||!keys||keys.cipherKey?.length!==32||keys.keyId!==context.keyId)
  throw new TypeError("Matching custody decryption key required");
 const aad=custodyAad(context);
 if(sha(aad)!==sealed.aadSha256)throw new Error("Custody AAD digest mismatch");
 if(sha(sealed.ciphertext)!==sealed.ciphertextSha256)throw new Error("Custody ciphertext checksum mismatch");
 const d=createDecipheriv("aes-256-gcm",keys.cipherKey,sealed.nonce,{authTagLength:16});
 d.setAAD(aad);d.setAuthTag(sealed.tag);
 const plain=Buffer.concat([d.update(sealed.ciphertext),d.final()]);
 if(sha(plain)!==context.sha256||plain.length!==context.byteCount)throw new Error("Custody plaintext checksum mismatch");
 return plain;
}
export function verifyScanMac(row,keys){
 if(!row||!keys||keys.macKey?.length!==32||row.key_id!==keys.keyId||
  !hex64(row.scanner_attestation_mac)||!hex64(row.ciphertext_sha256))return false;
 const context={tenantId:row.tenant_id,caseId:row.case_id,evidenceId:row.evidence_id,
  clientRequestId:row.client_request_id,actorId:row.received_by,
  sha256:row.sha256,byteCount:row.byte_count,mediaType:row.media_type,keyId:row.key_id};
 const observedAt=new Date(row.scan_observed_at).toISOString();
 const expected=createHmac("sha256",keys.macKey)
  .update(scanPayload(context,observedAt,row.ciphertext_sha256)).digest();
 return timingSafeEqual(expected,Buffer.from(row.scanner_attestation_mac,"hex"));
}
