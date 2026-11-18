// Isolated network plus actual crypto; no real records or external hosts.
import test from "node:test";
import assert from "node:assert/strict";
import {createHash,generateKeyPairSync,randomUUID} from "node:crypto";
import {privacyKeyFingerprint,privacyEnvelopeDigest,sealPrivacyResponse} from "../scripts/privacy-response-envelope.js";
import {issuePrivacyReceiptChallenge,openAndAcknowledgePrivacyResponse} from "../scripts/privacy-delivery-receipt.js";
import {startSyntheticCourier,syntheticCourierRequest} from "./support/synthetic-privacy-courier.js";
import {syntheticTlsFixture} from "./support/synthetic-tls-fixture.js";
const H=x=>createHash("sha256").update(x).digest("hex");
const tls=syntheticTlsFixture();
function fixture(){
 const recipient=generateKeyPairSync("x25519"),sender=generateKeyPairSync("ed25519"),signer=generateKeyPairSync("ed25519");
 const response=Buffer.from("Synthetic test response only");
 let now=Date.now();
 const ctx={tenantId:randomUUID(),caseId:randomUUID(),orderId:randomUUID(),recipientKeySha256:privacyKeyFingerprint(recipient.publicKey),senderKeySha256:privacyKeyFingerprint(sender.publicKey),responseSha256:H(response)};
 const envelope=sealPrivacyResponse(response,ctx,recipient.publicKey,sender.privateKey);
 const expected={...ctx,scopeSha256:H("synthetic approved scope"),envelopeSha256:privacyEnvelopeDigest(envelope),recipientSigningKeySha256:privacyKeyFingerprint(signer.publicKey),authorizedAt:new Date(now-1000).toISOString()};
 const challenge=issuePrivacyReceiptChallenge(expected,sender.privateKey,now);
 const setup={synthetic:true,expected,challenge,envelope,senderPublicKey:sender.publicKey,recipientSigningPublicKey:signer.publicKey,serverKey:tls.serverKey,serverCert:tls.serverCert,clientCert:tls.clientCert,clock:()=>now};
 return {setup,expected,response,recipientPrivateKey:recipient.privateKey,recipientSigningPrivateKey:signer.privateKey,senderPublicKey:sender.publicKey,advance:ms=>{now+=ms;},now:()=>now};
}
const call=(courier,path,receipt,changes={})=>syntheticCourierRequest({port:courier.port,token:courier.token,serverCert:tls.serverCert,serverPin:courier.serverPin,clientKey:tls.clientKey,clientCert:tls.clientCert,path,receipt,...changes});
function ack(f,data){return openAndAcknowledgePrivacyResponse({...data,expected:f.expected,recipientPrivateKey:f.recipientPrivateKey,recipientSigningPrivateKey:f.recipientSigningPrivateKey,senderPublicKey:f.senderPublicKey,now:f.now()});}
test("TLS pinned mutually authenticated single-use claim and signed receipt, including concurrent replay",async()=>{
 const f=fixture(),c=await startSyntheticCourier(f.setup);
 try{
  assert.equal(c.status().state,"ready");
  assert.equal((await call(c,"/receipt",{})).status,409);
  assert.equal((await call(c,"/claim",undefined,{token:"a".repeat(64)})).status,403);
  await assert.rejects(()=>call(c,"/claim",undefined,{serverPin:"b".repeat(64)}));
  await assert.rejects(()=>call(c,"/claim",undefined,{clientKey:tls.otherKey,clientCert:tls.otherCert}));
  await assert.rejects(()=>call(c,"/claim",undefined,{serverCert:tls.otherCert}));
  assert.equal(c.status().state,"ready");
  const claims=await Promise.all([call(c,"/claim"),call(c,"/claim")]);
  assert.deepEqual(claims.map(x=>x.status).sort(),[200,409]);
  const packageData=claims.find(x=>x.status===200).data;
  assert.ok(!JSON.stringify(packageData).includes(f.response.toString()));
  assert.equal(privacyEnvelopeDigest(packageData.envelope),f.expected.envelopeSha256);
  const receipt=ack(f,packageData);
  assert.equal((await call(c,"/receipt",{...receipt,signature:Buffer.alloc(64).toString("base64")})).status,403);
  assert.equal(c.status().state,"claimed");
  const receipts=await Promise.all([call(c,"/receipt",receipt),call(c,"/receipt",receipt)]);
  assert.deepEqual(receipts.map(x=>x.status).sort(),[200,409]);
  const result=receipts.find(x=>x.status===200).data;
  assert.equal(result.status,"recipient-signature-verified");assert.equal(result.deliveryVerified,false);
  assert.deepEqual(c.status().receiptEvidence,result);assert.equal(c.status().state,"acknowledged");
  assert.equal((await call(c,"/claim")).status,409);
 }finally{await c.close();}
});
test("expiry blocks both unclaimed and already claimed offers",async()=>{
 for(const claimed of [false,true]){
  const f=fixture(),c=await startSyntheticCourier(f.setup);
  try{
   let receipt;
   if(claimed){const data=(await call(c,"/claim")).data;receipt=ack(f,data);}
   f.advance(900000);
   assert.equal((await call(c,claimed?"/receipt":"/claim",receipt)).status,410);
   assert.equal(c.status().state,"expired");assert.equal(c.status().receiptEvidence,null);
  }finally{await c.close();}
 }
});
test("wrong approved envelope, changed challenge, recipient signer or non-synthetic mode rejected before listen",async()=>{
 const f=fixture();
 await assert.rejects(()=>startSyntheticCourier({...f.setup,synthetic:false}));
 await assert.rejects(()=>startSyntheticCourier({...f.setup,envelope:{...f.setup.envelope,tag:Buffer.alloc(16).toString("base64")}}));
 await assert.rejects(()=>startSyntheticCourier({...f.setup,challenge:{...f.setup.challenge,signature:Buffer.alloc(64).toString("base64")}}));
 await assert.rejects(()=>startSyntheticCourier({...f.setup,recipientSigningPublicKey:generateKeyPairSync("ed25519").publicKey}));
});
test("wrong recipient cannot acknowledge; a receipt from another release is denied",async()=>{
 const f=fixture(),other=fixture(),c=await startSyntheticCourier(f.setup);
 try{
  const data=(await call(c,"/claim")).data;
  assert.throws(()=>ack({...f,recipientPrivateKey:other.recipientPrivateKey},data));
  assert.equal((await call(c,"/receipt",ack(other,{envelope:other.setup.envelope,challenge:other.setup.challenge}))).status,403);
  assert.equal(c.status().state,"claimed");
 }finally{await c.close();}
});
