import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes,randomUUID} from "node:crypto";
import {sealAttachment,openQuarantinedAttachment,attachmentShape,independentAttachmentKey} from "../src/attachment-quarantine.js";
const body=Buffer.from("%PDF-1.7\nsynthetic test body\n");
const meta={tenantId:randomUUID(),batchId:randomUUID(),userId:randomUUID(),id:randomUUID(),type:"application/pdf",keyId:"test-key",size:body.length};
const key=randomBytes(32).toString("hex");
test("quarantine encryption authenticates exact tenant, uploader, attachment and metadata",()=>{
 const a=sealAttachment(body,meta,key),b=sealAttachment(body,meta,key);
 assert.notDeepEqual(a.nonce,b.nonce);assert.notDeepEqual(a.ciphertext,body);
 assert.deepEqual(openQuarantinedAttachment(a,meta,key),body);
 for(const patch of [{tenantId:randomUUID()},{batchId:randomUUID()},{userId:randomUUID()},{id:randomUUID()},{keyId:"other"},{type:"image/png"}])assert.throws(()=>openQuarantinedAttachment(a,{...meta,...patch},key),/authentication failed/);
 assert.throws(()=>openQuarantinedAttachment({...a,tag:Buffer.alloc(16)},meta,key),/authentication failed/);
 assert.throws(()=>openQuarantinedAttachment(a,meta,randomBytes(32).toString("hex")),/authentication failed/);
});
test("unsupported or excessive content and reused key material are refused",()=>{
 assert.equal(attachmentShape("application/zip",body),false);
 assert.equal(attachmentShape("application/pdf",Buffer.from("not PDF file")),false);
 assert.equal(attachmentShape("application/pdf",Buffer.alloc(262145)),false);
 assert.throws(()=>independentAttachmentKey({ATTACHMENT_ENCRYPTION_KEY:key,ATTACHMENT_ENCRYPTION_KEY_ID:"test",TENANT_CONTEXT_HMAC_SECRET:key.toUpperCase()}),/Independent/);
 assert.equal(independentAttachmentKey({ATTACHMENT_ENCRYPTION_KEY:key,ATTACHMENT_ENCRYPTION_KEY_ID:"test"}).keyId,"test");
});
