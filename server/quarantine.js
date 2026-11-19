import {createCipheriv,createDecipheriv,createHash,randomBytes} from "node:crypto";
import {TextDecoder} from "node:util";
export const MAX_QUARANTINE_BYTES=65536;
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const hex=/^[0-9a-f]{64}$/;
const keyId=/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;

export function quarantineConfig(env=process.env){
 // Do not enable against real customer data before independent scanner,
 // deletion/lifecycle and private hosting acceptance are implemented.
 if(env.NODE_ENV==="production"||env.QUARANTINE_UPLOADS_ENABLED!=="true")return null;
 const id=env.QUARANTINE_KEY_ID||"",secret=env.QUARANTINE_ENCRYPTION_KEY||"";
 if(!keyId.test(id)||!hex.test(secret)||[env.TENANT_CONTEXT_HMAC_SECRET,env.RATE_LIMIT_HASH_SECRET,env.BACKUP_ENCRYPTION_KEY].some(x=>x?.toLowerCase()===secret))throw new Error("Independent quarantine encryption configuration required");
 return {id,secret};
}
function aad(tenant,batch,sha,id){
 if(!uuid.test(tenant)||!uuid.test(batch)||!hex.test(sha)||!keyId.test(id))throw new Error("Invalid quarantine identity");
 return Buffer.from(JSON.stringify(["profitpilot-quarantine-v1",tenant,batch,sha,id]));
}
function keyMaterial(secret){if(typeof secret!=="string"||!hex.test(secret))throw new Error("Invalid quarantine key");return Buffer.from(secret,"hex");}
export function sealQuarantine(bytes,tenant,batch,config){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>MAX_QUARANTINE_BYTES)throw new Error("Invalid upload size");
 // Strict UTF-8 text, not archives, executable files, NUL or other control bytes.
 // This check is not a malware scan, nor a parser or DLP guarantee.
 const text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);
 if(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u.test(text)||!text.trim())throw new Error("Unsupported file content");
 const sha=createHash("sha256").update(bytes).digest("hex");
 const nonce=randomBytes(12),key=keyMaterial(config.secret);
 try{
  const cipher=createCipheriv("aes-256-gcm",key,nonce,{authTagLength:16});
  cipher.setAAD(aad(tenant,batch,sha,config.id));
  const ciphertext=Buffer.concat([cipher.update(bytes),cipher.final()]);
  return {sha,keyId:config.id,nonce,tag:cipher.getAuthTag(),ciphertext};
 }finally{key.fill(0);}
}
// Intended only for isolated scanner/recovery workers. No API route decrypts or serves bytes.
export function openQuarantine(envelope,tenant,batch,config){
 if(envelope.keyId!==config.id||!Buffer.isBuffer(envelope.nonce)||envelope.nonce.length!==12||
 !Buffer.isBuffer(envelope.tag)||envelope.tag.length!==16||!Buffer.isBuffer(envelope.ciphertext)||envelope.ciphertext.length<1||envelope.ciphertext.length>MAX_QUARANTINE_BYTES)throw new Error("Invalid quarantine envelope");
 const key=keyMaterial(config.secret);
 let intermediate,final,plain;
 try{
  const decipher=createDecipheriv("aes-256-gcm",key,envelope.nonce,{authTagLength:16});
  decipher.setAAD(aad(tenant,batch,envelope.sha,envelope.keyId));decipher.setAuthTag(envelope.tag);
  intermediate=decipher.update(envelope.ciphertext);final=decipher.final();
  plain=Buffer.concat([intermediate,final]);
  if(createHash("sha256").update(plain).digest("hex")!==envelope.sha){plain.fill(0);throw new Error("Quarantine checksum mismatch");}
  return plain;
 }finally{key.fill(0);intermediate?.fill(0);final?.fill(0);}
}
