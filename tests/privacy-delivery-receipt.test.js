import test from "node:test";
import assert from "node:assert/strict";
import {createHash,generateKeyPairSync,randomUUID,sign} from "node:crypto";
import {privacyKeyFingerprint,sealPrivacyResponse,privacyEnvelopeDigest} from "../scripts/privacy-response-envelope.js";
import {issuePrivacyReceiptChallenge,openAndAcknowledgePrivacyResponse,verifyPrivacyReceipt} from "../scripts/privacy-delivery-receipt.js";
const H=x=>createHash("sha256").update(x).digest("hex"),now=Date.parse("2035-01-02T12:00:00.000Z");
const recipient=generateKeyPairSync("x25519"),sender=generateKeyPairSync("ed25519"),recipientSigning=generateKeyPairSync("ed25519"),other=generateKeyPairSync("ed25519"),otherRecipient=generateKeyPairSync("x25519");
function fixture(){
 const response=Buffer.from("Synthetic privacy receipt fixture");
 const ctx={tenantId:randomUUID(),caseId:randomUUID(),orderId:randomUUID(),recipientKeySha256:privacyKeyFingerprint(recipient.publicKey),senderKeySha256:privacyKeyFingerprint(sender.publicKey),responseSha256:H(response)};
 const envelope=sealPrivacyResponse(response,ctx,recipient.publicKey,sender.privateKey);
 const expected={...ctx,scopeSha256:H("approved scope"),envelopeSha256:privacyEnvelopeDigest(envelope),recipientSigningKeySha256:privacyKeyFingerprint(recipientSigning.publicKey),authorizedAt:new Date(now-1000).toISOString()};
 const challenge=issuePrivacyReceiptChallenge(expected,sender.privateKey,now);
 const f={challenge,expected,envelope:{...envelope},recipientPrivateKey:recipient.privateKey,recipientSigningPrivateKey:recipientSigning.privateKey,senderPublicKey:sender.publicKey,recipientSigningPublicKey:recipientSigning.publicKey,now:now+1000};
 f.receipt=openAndAcknowledgePrivacyResponse(f);
 return f;
}
test("decrypt exact response, sign fresh challenge and verify acknowledgement without asserting delivery",()=>{
 const f=fixture(),r=verifyPrivacyReceipt(f);assert.equal(r.status,"recipient-signature-verified");assert.equal(r.deliveryVerified,false);
 assert.match(r.receiptDigest,/^[a-f0-9]{64}$/);assert.equal(r.receiptKeyDigest,f.expected.recipientSigningKeySha256);
 assert.deepEqual(verifyPrivacyReceipt(f),r);assert.ok(!JSON.stringify(f.receipt).includes(f.expected.responseSha256));
});
const cases=[
 ["other tenant",f=>{f.expected.tenantId=randomUUID();}],
 ["other case",f=>{f.expected.caseId=randomUUID();}],
 ["other order",f=>{f.expected.orderId=randomUUID();}],
 ["other approved scope",f=>{f.expected.scopeSha256=H("substitute");}],
 ["other envelope",f=>{f.expected.envelopeSha256=H("substitute");}],
 ["other response",f=>{f.expected.responseSha256=H("substitute");}],
 ["other sender",f=>{f.senderPublicKey=other.publicKey;}],
 ["other recipient signer",f=>{f.recipientSigningPublicKey=other.publicKey;}],
 ["changed signed challenge",f=>{f.challenge.record.nonce=H("tampered");}],
 ["second challenge replay",f=>{f.challenge=issuePrivacyReceiptChallenge(f.expected,sender.privateKey,now);}],
 ["forged recipient signature",f=>{f.receipt.signature=Buffer.alloc(64).toString("base64");}],
 ["forged sender signature",f=>{f.challenge.signature=Buffer.alloc(64).toString("base64");}],
 ["unexpected receipt fields",f=>{f.receipt.record.delivered=true;}],
 ["backdated acknowledgement",f=>{f.receipt.record.acknowledgedAt=new Date(now-1).toISOString();}],
 ["future acknowledgement",f=>{f.now=now;}],
 ["late reconciliation",f=>{f.now=now+86401001;}],
 ["self-signed recipient",f=>{f.expected.recipientSigningKeySha256=f.expected.senderKeySha256;f.recipientSigningPublicKey=sender.publicKey;}],
 ["expired signer statement even if correctly signed",f=>{const r=f.receipt.record;r.acknowledgedAt=new Date(now+900000).toISOString();f.now=now+900001;f.receipt.signature=sign(null,Buffer.from(JSON.stringify(["profitpilot-privacy-receipt-v1",r.challengeSha256,r.acknowledgedAt])),recipientSigning.privateKey).toString("base64");}]
];
for(const [name,change] of cases)test(name,()=>{const f=fixture();change(f);assert.throws(()=>verifyPrivacyReceipt(f));});
for(const [name,change] of [
 ["incorrect decryption key",f=>{f.recipientPrivateKey=otherRecipient.privateKey;}],
 ["incorrect signing key",f=>{f.recipientSigningPrivateKey=other.privateKey;}],
 ["changed envelope",f=>{f.envelope.tag=Buffer.alloc(16).toString("base64");}],
 ["expired challenge",f=>{f.now=now+900000;}]
])test(name+" cannot create acknowledgement",()=>{const f=fixture();change(f);assert.throws(()=>openAndAcknowledgePrivacyResponse(f));});
test("cannot issue a stale, future or wrong-key release challenge",()=>{const f=fixture();for(const n of [now-2000,now+900000])assert.throws(()=>issuePrivacyReceiptChallenge(f.expected,sender.privateKey,n));assert.throws(()=>issuePrivacyReceiptChallenge(f.expected,other.privateKey,now));});
