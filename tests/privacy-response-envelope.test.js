import test from "node:test";
import assert from "node:assert/strict";
import {generateKeyPairSync,createHash,randomUUID} from "node:crypto";
import {privacyKeyFingerprint,privacyEnvelopeDigest,sealPrivacyResponse,openPrivacyResponse} from "../scripts/privacy-response-envelope.js";
const hash=x=>createHash("sha256").update(x).digest("hex");
const recipient=generateKeyPairSync("x25519"),sender=generateKeyPairSync("ed25519"),otherRecipient=generateKeyPairSync("x25519"),otherSender=generateKeyPairSync("ed25519");
function fixture(){
 const response=Buffer.from("Synthetic confidential privacy response");
 const context={tenantId:randomUUID(),caseId:randomUUID(),orderId:randomUUID(),recipientKeySha256:privacyKeyFingerprint(recipient.publicKey),senderKeySha256:privacyKeyFingerprint(sender.publicKey),responseSha256:hash(response)};
 const envelope=sealPrivacyResponse(response,context,recipient.publicKey,sender.privateKey);
 return {response,context,envelope:{...envelope},digest:privacyEnvelopeDigest(envelope),recipient:recipient.privateKey,sender:sender.publicKey};
}
const open=f=>openPrivacyResponse(f.envelope,f.context,f.digest,f.recipient,f.sender);
test("only the exact approved recipient decrypts the signed response",()=>{const f=fixture();assert.deepEqual(open(f),f.response);assert.ok(!JSON.stringify(f.envelope).includes(f.response.toString()));assert.ok(!JSON.stringify(f.envelope).includes(f.context.responseSha256));assert.notEqual(privacyEnvelopeDigest(sealPrivacyResponse(f.response,f.context,recipient.publicKey,sender.privateKey)),f.digest);});
const cases=[
 ["other tenant",f=>{f.context.tenantId=randomUUID();}],
 ["other case",f=>{f.context.caseId=randomUUID();}],
 ["other order",f=>{f.context.orderId=randomUUID();}],
 ["other response hash",f=>{f.context.responseSha256=hash("other");}],
 ["other recipient key",f=>{f.recipient=otherRecipient.privateKey;}],
 ["other sender key",f=>{f.sender=otherSender.publicKey;}],
 ["other approved envelope",f=>{f.digest=hash("other");}],
 ["forged ciphertext rehashed",f=>{const b=Buffer.from(f.envelope.ciphertext,"base64");b[0]^=1;f.envelope.ciphertext=b.toString("base64");f.digest=privacyEnvelopeDigest(f.envelope);}],
 ["forged tag rehashed",f=>{f.envelope.tag=Buffer.alloc(16).toString("base64");f.digest=privacyEnvelopeDigest(f.envelope);}],
 ["forged ephemeral key rehashed",f=>{f.envelope.ephemeralKey=otherRecipient.publicKey.export({format:"der",type:"spki"}).toString("base64");f.digest=privacyEnvelopeDigest(f.envelope);}],
 ["forged signature rehashed",f=>{f.envelope.signature=Buffer.alloc(64).toString("base64");f.digest=privacyEnvelopeDigest(f.envelope);}],
 ["noncanonical base64",f=>{f.envelope.iv+="=";}],
 ["unexpected fields",f=>{f.envelope.plaintext="leak";}],
 ["oversized ciphertext",f=>{f.envelope.ciphertext=Buffer.alloc(1048577).toString("base64");}],
 ["wrong key type",f=>{f.recipient=sender.privateKey;}],
 ["unapproved extra context",f=>{f.context.recipientEmail="synthetic@example.invalid";}]
];
for(const [name,change] of cases)test(name,()=>{const f=fixture();change(f);assert.throws(()=>open(f));});
test("sender refuses wrong pinned recipient or altered plaintext",()=>{const f=fixture();assert.throws(()=>sealPrivacyResponse(f.response,f.context,otherRecipient.publicKey,sender.privateKey));assert.throws(()=>sealPrivacyResponse(Buffer.from("changed"),f.context,recipient.publicKey,sender.privateKey));assert.throws(()=>sealPrivacyResponse(f.response,f.context,recipient.publicKey,otherSender.privateKey));});
test("maximum envelope size supported, larger or empty response rejected",()=>{const f=fixture(),response=Buffer.alloc(1048576,42),context={...f.context,responseSha256:hash(response)};const e=sealPrivacyResponse(response,context,recipient.publicKey,sender.privateKey);assert.deepEqual(openPrivacyResponse(e,context,privacyEnvelopeDigest(e),recipient.privateKey,sender.publicKey),response);for(const invalid of [Buffer.alloc(0),Buffer.alloc(1048577)])assert.throws(()=>sealPrivacyResponse(invalid,{...context,responseSha256:hash(invalid)},recipient.publicKey,sender.privateKey));});
