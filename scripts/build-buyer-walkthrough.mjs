#!/usr/bin/env node
// Deterministically build the distributable single-file synthetic buyer walkthrough.
// No npm install, network, external assets or runtime browser imports required.
import {readFileSync,writeFileSync} from "node:fs";
import {dirname,join,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import assert from "node:assert/strict";
const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
const sourcePath=join(root,"src/buyer-walkthrough-core.js");
const templatePath=join(root,"demo/buyer-walkthrough.shell.html");
const outputPath=join(root,"demo/buyer-walkthrough.html");
const marker="/*__BUYER_DEMO_CORE__*/";
function build(){
 const src=readFileSync(sourcePath,"utf8"),shell=readFileSync(templatePath,"utf8");
 assert.equal(shell.split(marker).length,2,"Exactly one buyer core marker required");
 // Only known ES module export forms are accepted for inlining.
 const engine=src.replace(/^export (?=(?:const|function)\b)/gm,"");
 assert.doesNotMatch(engine,/^\s*(?:import|export)\s/gm,"Buyer demo core must have no dependencies");
 assert.doesNotMatch(engine,/<\/script\s*>/i,"Script close tag forbidden inside generated engine");
 assert.doesNotMatch(shell,/<script[^>]+src\s*=/i,"Standalone buyer demo must not load external scripts");
 const result=shell.replace(marker,engine);
 assert.equal(result.includes(marker),false);
 return result;
}
const action=process.argv[2];
if(process.argv.length!==3||!["--check","--write"].includes(action))
 throw Error("Usage: node scripts/build-buyer-walkthrough.mjs --write | --check");
const built=build();
if(action==="--write"){
 writeFileSync(outputPath,built,"utf8");
 process.stdout.write("Generated standalone synthetic buyer walkthrough\n");
}else{
 assert.equal(readFileSync(outputPath,"utf8"),built,
  "Buyer walkthrough is stale: rerun --write and commit generated HTML");
 process.stdout.write("Single-file buyer walkthrough matches audited source/template\n");
}
