import test from "node:test";
import assert from "node:assert/strict";
import {randomBytes} from "node:crypto";
import {mkdtemp,readFile,writeFile,stat,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {sealDump,openDump,sealFile,openFile} from "../scripts/encrypted-pg-backup.js";
const options={key:randomBytes(32).toString("hex"),deploymentId:"ci-deployment",backupId:"backup-ci",checkpointSha256:"ab".repeat(32)};
const dump=Buffer.from("PGDMP synthetic backup with confidential test values");
test("backup envelope authenticates dump and exact deployment, backup and checkpoint",()=>{
 const a=sealDump(dump,options),b=sealDump(dump,options);
 assert.notDeepEqual(a,b,"fresh random nonce");
 assert.equal(a.includes(dump),false);
 assert.deepEqual(openDump(a,options).dump,dump);
 assert.throws(()=>openDump(a,{...options,deploymentId:"other-deployment"}),/identity or checkpoint/);
 assert.throws(()=>openDump(a,{...options,checkpointSha256:"cd".repeat(32)}),/identity or checkpoint/);
 assert.throws(()=>openDump(a,{...options,backupId:"other-backup"}),/identity or checkpoint/);
 for(const index of [6,20,a.length-1]){
  const changed=Buffer.from(a);changed[index]^=1;
  assert.throws(()=>openDump(changed,options),/authentication failed/);
 }
 assert.throws(()=>openDump(a,{...options,key:"12".repeat(32)}),/authentication failed/);
 assert.throws(()=>sealDump(Buffer.from("not a dump"),options),/custom-format/);
});
test("backup open rejects tampering before any plaintext output and never overwrites",async()=>{
 const dir=await mkdtemp(join(tmpdir(),"pp-archive-"));
 try{
  const inFile=join(dir,"input.dump"),sealed=join(dir,"backup.enc"),out=join(dir,"output.dump"),bad=join(dir,"bad.enc");
  await writeFile(inFile,dump,{mode:0o600});
  await sealFile(inFile,sealed,options);
  assert.equal((await stat(sealed)).mode&0o777,0o600);
  await assert.rejects(()=>sealFile(inFile,sealed,options),/EEXIST/);
  const changed=await readFile(sealed);changed[changed.length-1]^=1;await writeFile(bad,changed);
  await assert.rejects(()=>openFile(bad,out,options),/authentication failed/);
  await assert.rejects(()=>stat(out),/ENOENT/);
  await openFile(sealed,out,options);
  assert.deepEqual(await readFile(out),dump);
  assert.equal((await stat(out)).mode&0o777,0o600);
  await assert.rejects(()=>openFile(sealed,out,options),/EEXIST/);
 }finally{await rm(dir,{recursive:true,force:true});}
});
