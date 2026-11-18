// Offline assisted privacy response envelope. No network, storage or release
// authorisation. Independently verify the recipient key and sender pin and use
// the exact approved database scope; never fetch a key from an untrusted bundle.
import {createHash,createPublicKey,generateKeyPairSync,diffieHellman,hkdfSync,randomBytes,createCipheriv,createDecipheriv,sign,verify} from "node:crypto";
const FORMAT="profitpilot-privacy-envelope-v1",MAX=1048576;
const FIELDS=["tenantId","caseId","orderId","recipientKeySha256","senderKeySha256","responseSha256"];
const ENVELOPE=["format","ephemeralKey","iv","ciphertext","tag","signature"];
const exact=(x,keys)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const hex=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x)&&!/^0+$/.test(x);
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(x);
const hash=x=>createHash("sha256").update(x).digest("hex");
const bytes=x=>Buffer.from(JSON.stringify(x),"utf8");
const deny=()=>{throw Error("Privacy response envelope denied");};
const pub=(k,type)=>{if(k?.type!=="public"||k.asymmetricKeyType!==type)deny();return k;};
const priv=(k,type)=>{if(k?.type!=="private"||k.asymmetricKeyType!==type)deny();return k;};
export function privacyKeyFingerprint(k){if(k?.type!=="public"||!["ed25519","x25519"].includes(k.asymmetricKeyType))deny();return hash(k.export({type:"spki",format:"der"}));}
function aad(c){
 if(!exact(c,FIELDS)||![c.tenantId,c.caseId,c.orderId].every(uuid)||![c.recipientKeySha256,c.senderKeySha256,c.responseSha256].every(hex)||c.recipientKeySha256===c.senderKeySha256)deny();
 return bytes([FORMAT,...FIELDS.map(k=>c[k])]);
}
function b64(s,max,exactLength){
 if(typeof s!=="string"||s.length<4||s.length>Math.ceil(max/3)*4||!/^[A-Za-z0-9+/]+={0,2}$/.test(s))deny();
 const b=Buffer.from(s,"base64");
 if(b.length<1||b.length>max||(exactLength!==undefined&&b.length!==exactLength)||b.toString("base64")!==s)deny();
 return b;
}
function canonicalParts(e){
 if(!exact(e,ENVELOPE)||e.format!==FORMAT)deny();
 const ephemeral=b64(e.ephemeralKey,44,44),iv=b64(e.iv,12,12),ciphertext=b64(e.ciphertext,MAX),tag=b64(e.tag,16,16),signature=b64(e.signature,64,64);
 return {ephemeral,iv,ciphertext,tag,signature};
}
export function privacyEnvelopeDigest(e){
 canonicalParts(e);
 return hash(bytes(ENVELOPE.map(k=>e[k])));
}
function signBytes(e,associated){return bytes(["profitpilot-privacy-envelope-signature-v1",associated.toString("base64"),...ENVELOPE.slice(0,-1).map(k=>e[k])]);}
function derive(privateKey,publicKey,associated){
 const shared=diffieHellman({privateKey,publicKey});
 try{
  if(shared.equals(Buffer.alloc(32)))deny();
  return Buffer.from(hkdfSync("sha256",shared,createHash("sha256").update(associated).digest(),Buffer.from("profitpilot-privacy-envelope-key-v1"),32));
 }finally{shared.fill(0);}
}
export function sealPrivacyResponse(response,context,recipientPublicKey,senderPrivateKey){
 const associated=aad(context);
 pub(recipientPublicKey,"x25519");priv(senderPrivateKey,"ed25519");
 if(!Buffer.isBuffer(response)||response.length<1||response.length>MAX||hash(response)!==context.responseSha256||
 privacyKeyFingerprint(recipientPublicKey)!==context.recipientKeySha256||
 privacyKeyFingerprint(createPublicKey(senderPrivateKey))!==context.senderKeySha256)deny();
 const ephemeral=generateKeyPairSync("x25519"),iv=randomBytes(12),key=derive(ephemeral.privateKey,recipientPublicKey,associated);
 try{
  const cipher=createCipheriv("aes-256-gcm",key,iv,{authTagLength:16});cipher.setAAD(associated);
  const ciphertext=Buffer.concat([cipher.update(response),cipher.final()]);
  const e={format:FORMAT,ephemeralKey:ephemeral.publicKey.export({type:"spki",format:"der"}).toString("base64"),iv:iv.toString("base64"),ciphertext:ciphertext.toString("base64"),tag:cipher.getAuthTag().toString("base64"),signature:""};
  e.signature=sign(null,signBytes(e,associated),senderPrivateKey).toString("base64");
  return Object.freeze(e);
 }finally{key.fill(0);}
}
export function openPrivacyResponse(e,context,approvedEnvelopeSha256,recipientPrivateKey,senderPublicKey){
 const associated=aad(context),parts=canonicalParts(e);
 priv(recipientPrivateKey,"x25519");pub(senderPublicKey,"ed25519");
 if(!hex(approvedEnvelopeSha256)||privacyEnvelopeDigest(e)!==approvedEnvelopeSha256||
 privacyKeyFingerprint(createPublicKey(recipientPrivateKey))!==context.recipientKeySha256||
 privacyKeyFingerprint(senderPublicKey)!==context.senderKeySha256||
 !verify(null,signBytes(e,associated),senderPublicKey,parts.signature))deny();
 const ephemeral=pub(createPublicKey({key:parts.ephemeral,type:"spki",format:"der"}),"x25519");
 if(!ephemeral.export({type:"spki",format:"der"}).equals(parts.ephemeral))deny();
 const key=derive(recipientPrivateKey,ephemeral,associated);
 let partial,tail,result;
 try{
  const decipher=createDecipheriv("aes-256-gcm",key,parts.iv,{authTagLength:16});
  decipher.setAAD(associated);decipher.setAuthTag(parts.tag);
  partial=decipher.update(parts.ciphertext);tail=decipher.final();result=Buffer.concat([partial,tail]);
  if(hash(result)!==context.responseSha256){result.fill(0);deny();}
  return result;
 }finally{key.fill(0);partial?.fill(0);tail?.fill(0);}
}
