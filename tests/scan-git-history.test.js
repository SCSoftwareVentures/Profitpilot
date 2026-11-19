import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,writeFileSync,rmSync} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {execFileSync} from "node:child_process";
import {scanHistory} from "../scripts/scan-git-history.js";
test("history scanner finds removed credential shapes and renamed sensitive files without logging values",async()=>{
 const dir=mkdtempSync(join(tmpdir(),"pp-history-"));
 const git=(...args)=>execFileSync("git",args,{cwd:dir,stdio:"pipe"});
 try{
  git("init","-q");git("config","user.name","CI fixture");git("config","user.email","fixture@example.invalid");
  writeFileSync(join(dir,"safe.txt"),"synthetic");git("add",".");git("commit","-qm","first");
  assert.equal((await scanHistory({cwd:dir})).findings,0);
  const token="gh"+"p_"+"x".repeat(36);
  writeFileSync(join(dir,"removed.txt"),token);
  writeFileSync(join(dir,".env.production"),"synthetic");git("add",".");git("commit","-qm","second");
  git("rm","removed.txt",".env.production");git("commit","-qm","remove");
  const events=[],result=await scanHistory({cwd:dir,emit:e=>events.push(e)});
  assert.equal(result.findings,2);assert.ok(events.some(e=>e.category==="GitHub token"));assert.ok(events.some(e=>e.event==="history_filename_finding"));
  assert.ok(!JSON.stringify(events).includes(token));assert.ok(!JSON.stringify(events).includes(".env.production"));
 }finally{rmSync(dir,{recursive:true,force:true});}
});
test("history scanner denies shallow checkout",async()=>{
 const dir=mkdtempSync(join(tmpdir(),"pp-shallow-")),source=join(dir,"source"),clone=join(dir,"clone");
 try{
  execFileSync("git",["init","-q",source]);const git=(...args)=>execFileSync("git",args,{cwd:source,stdio:"pipe"});
  git("config","user.name","CI fixture");git("config","user.email","fixture@example.invalid");
  writeFileSync(join(source,"a"),"a");git("add",".");git("commit","-qm","one");
  execFileSync("git",["clone","-q","--depth","1","file://"+source,clone]);
  await assert.rejects(()=>scanHistory({cwd:clone}),/Complete reachable history required/);
 }finally{rmSync(dir,{recursive:true,force:true});}
});
