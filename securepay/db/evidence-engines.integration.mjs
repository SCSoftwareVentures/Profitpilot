// Runs only in the dedicated engine CI job with provisioned Pillow and ClamAV.
import test from "node:test";
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {mkdtemp,writeFile,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {createHash,randomBytes,randomUUID} from "node:crypto";
import {jpegNormalizer,validEvidencePNG,clamavScanner,makeEvidenceScanner} from "./evidence-scanner.mjs";
const generate=(width,height)=>{
 const r=spawnSync("/usr/bin/python3",["-I","-c",`import sys
from PIL import Image
im=Image.new("RGB",(${width},${height}),(42,90,160))
exif=Image.Exif()
exif[270]="synthetic private metadata"
im.save(sys.stdout.buffer,"JPEG",exif=exif)
`],{maxBuffer:2097152,timeout:5000});
 assert.equal(r.status,0);return r.stdout;
};
test("real Pillow decoder removes metadata and rejects malformed and oversized images",async()=>{
 const decode=jpegNormalizer(),input=generate(64,32),output=await decode(input);
 assert.ok(Buffer.isBuffer(output));assert.equal(validEvidencePNG(output),true);
 assert.equal(output.includes(Buffer.from("synthetic private metadata")),false);
 assert.equal(output.readUInt32BE(16),64);assert.equal(output.readUInt32BE(20),32);
 assert.equal(await decode(input.subarray(0,-2)),null);
 assert.equal(await decode(Buffer.concat([input,Buffer.from("trailing")])),null);
 assert.equal(await decode(generate(4096,1000)),null);
 assert.equal(await jpegNormalizer({executable:"/nonexistent/python"})(input),null);
});
test("real ClamAV engine detects a known harmless synthetic hash signature and denies unavailable engine",async()=>{
 const dir=await mkdtemp(join(tmpdir(),"sp-scan-"));
 try{
  const fixture=Buffer.from("SecurePay harmless synthetic antivirus detection fixture; never executable.");
  const db=join(dir,"fixture.hdb"),md5=createHash("md5").update(fixture).digest("hex");
  await writeFile(db,md5+":"+fixture.length+":SecurePay.Test.Fixture\n",{mode:0o600});
  const scan=clamavScanner({database:db,timeoutMs:30000});
  assert.equal(await scan(fixture),"infected");
  const clean=generate(64,32);
  assert.equal(await scan(clean),"clean");
  const decoder=jpegNormalizer();
  const signer=makeEvidenceScanner({key:randomBytes(32),scan,normalizeJPEG:decoder});
  const scope={photoId:randomUUID(),tenantId:randomUUID(),milestoneId:randomUUID(),caseId:randomUUID(),actorId:randomUUID(),mediaType:"image/jpeg"};
  const attested=await signer.attest({...scope,content:clean});
  assert.ok(attested&&validEvidencePNG(attested.content));
  assert.equal(attested.originalDigest,createHash("sha256").update(clean).digest("hex"));
  assert.equal(await signer.attest({...scope,content:fixture}),null);
  assert.equal(await clamavScanner({executable:"/nonexistent/clamscan"})(clean),"unavailable");
  assert.equal(await clamavScanner({database:join(dir,"missing.hdb")})(clean),"unavailable");
 }finally{await rm(dir,{recursive:true,force:true});}
});
