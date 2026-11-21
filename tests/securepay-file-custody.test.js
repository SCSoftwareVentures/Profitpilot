import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {validCustodyHeaders,verifyCustodyBytes,sameCustodyReceipt,MAX_CUSTODY_BYTES} from "../src/securepay-file-custody.js";
const id="11111111-1111-4111-8111-111111111111";
const bytes=Buffer.from("Harmless synthetic dispute evidence.\n");
const hash=createHash("sha256").update(bytes).digest("hex");
test("S9 validates bounded original bytes, exact hash and shallow media type",()=>{
 assert.equal(validCustodyHeaders({clientRequestId:id,declaredSha256:hash,mediaType:"text/plain"}),true);
 assert.equal(validCustodyHeaders({clientRequestId:id,declaredSha256:hash,mediaType:"text/html"}),false);
 assert.equal(validCustodyHeaders({clientRequestId:id,declaredSha256:hash,mediaType:"text/plain",contentEncoding:"gzip"}),false);
 const v=verifyCustodyBytes(bytes,hash,"text/plain");
 assert.equal(v.sha256,hash);assert.equal(v.sourceAuthenticityVerified,false);
 for(const [b,h,type] of [[bytes,"a".repeat(64),"text/plain"],[Buffer.from([0,65,66]),hash,"text/plain"],
 [Buffer.alloc(MAX_CUSTODY_BYTES+1,65),hash,"text/plain"],[bytes,hash,"application/pdf"],
 [bytes,hash,"image/png"],[bytes,hash,"image/jpeg"]])assert.throws(()=>verifyCustodyBytes(b,h,type));
});
test("S9 exact replay is bound to actor, digest, media type and request",()=>{
 const row={client_request_id:id,received_by:id,sha256:hash,media_type:"text/plain"};
 assert.equal(sameCustodyReceipt(row,{clientRequestId:id,sha256:hash,mediaType:"text/plain"},id),true);
 assert.equal(sameCustodyReceipt(row,{clientRequestId:id,sha256:"b".repeat(64),mediaType:"text/plain"},id),false);
 assert.equal(sameCustodyReceipt(row,{clientRequestId:id,sha256:hash,mediaType:"image/png"},id),false);
 assert.equal(sameCustodyReceipt(row,{clientRequestId:id,sha256:hash,mediaType:"text/plain"},"22222222-2222-4222-8222-222222222222"),false);
});
