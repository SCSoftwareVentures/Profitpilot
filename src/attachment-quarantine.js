// Opaque encrypted quarantine contents. No parser, scanner bypass or content-serving path.
import {createCipheriv,createDecipheriv,createHash,randomBytes} from "node:crypto";
export const MAX_ATTACHMENT_BYTES=256*1024;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KEY_ID=/^[A-Za-z0-9._-]{1,64}$/;
const HEX=/^[a-f0-9]{64}$/i;
const TYPES=["application/pdf","image/png","image/jpeg"];
function secret(key){
 if(typeof key!=="string"||!HEX.test(key))throw Error("Independent attachment encryption key required");
 return Buffer.from(key,"hex");
}
export function attachmentShape(type,body){
 if(!(body instanceof Buffer)||typeof type!=="string")return false;
 if(body.length<8||body.length>MAX_ATTACHMENT_BYTES||!TYPES.includes(type))return false;
 if(type==="application/pdf")return /^%PDF-1\.[0-7]/.test(body.subarray(0,8).toString("ascii"));
 if(type==="image/png")return body.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
 return body[0]===255&&body[1]===216&&body[2]===255;
}
function context(meta){
 const {tenantId,batchId,userId,id,type,keyId,size}=meta;
 if(![tenantId,batchId,userId,id].every(v=>typeof v==="string"&&UUID.test(v))||
 typeof keyId!=="string"||!KEY_ID.test(keyId)||typeof type!=="string"||!TYPES.includes(type)||!Number.isSafeInteger(size)||size<8||size>MAX_ATTACHMENT_BYTES)throw Error("Invalid attachment context");
 return Buffer.from(["profitpilot-quarantine-v1",tenantId,batchId,userId,id,type,keyId,String(size)].join("\n"),"utf8");
}
export function sealAttachment(body,meta,key){
 if(!(body instanceof Buffer)||!meta||typeof meta!=="object"||Array.isArray(meta)||!attachmentShape(meta.type,body)||meta.size!==body.length)throw Error("Unsupported or oversized attachment");
 const aad=context(meta),material=secret(key),nonce=randomBytes(12);
 try{
  const cipher=createCipheriv("aes-256-gcm",material,nonce,{authTagLength:16});cipher.setAAD(aad);
  const ciphertext=Buffer.concat([cipher.update(body),cipher.final()]);
  return {ciphertext,nonce,tag:cipher.getAuthTag()};
 }finally{material.fill(0);}
}
// Intended for trusted offline inspection only; not wired to any download route.
export function openQuarantinedAttachment(record,meta,key){
 const aad=context(meta),material=secret(key);
 let plain;
 try{
  if(!Buffer.isBuffer(record.ciphertext)||record.ciphertext.length!==meta.size||!Buffer.isBuffer(record.nonce)||record.nonce.length!==12||!Buffer.isBuffer(record.tag)||record.tag.length!==16)throw Error("Invalid envelope");
  const decipher=createDecipheriv("aes-256-gcm",material,record.nonce,{authTagLength:16});decipher.setAAD(aad);decipher.setAuthTag(record.tag);
  plain=decipher.update(record.ciphertext);
  const tail=decipher.final();
  const result=Buffer.concat([plain,tail]);tail.fill(0);
  if(!attachmentShape(meta.type,result)){result.fill(0);throw Error("Unsupported content");}
  return result;
 }catch{throw Error("Attachment authentication failed");}
 finally{material.fill(0);plain?.fill(0);}
}
export function attachmentWriteAction(meta,record){
 return "quarantine_attachment:"+[meta.id,meta.type,meta.keyId,String(meta.size),record.nonce.toString("hex"),record.tag.toString("hex"),createHash("sha256").update(record.ciphertext).digest("hex")].join(":");
}
export function independentAttachmentKey(env){
 const key=env.ATTACHMENT_ENCRYPTION_KEY,keyId=env.ATTACHMENT_ENCRYPTION_KEY_ID;
 if(typeof key!=="string"||!HEX.test(key)||typeof keyId!=="string"||!KEY_ID.test(keyId)||[env.TENANT_CONTEXT_HMAC_SECRET,env.PRIVACY_BACKUP_ENCRYPTION_KEY,env.PRIVACY_CHECKPOINT_KEY].some(k=>typeof k==="string"&&k.toLowerCase()===key.toLowerCase()))throw Error("Independent attachment key unavailable");
 return {key,keyId};
}
