#!/usr/bin/env node
// Creates a fixture representing the former Compose SQL mounts. No real schema is changed.
import {readFileSync,writeFileSync} from "node:fs";
import {dirname,resolve} from "node:path";
import {fileURLToPath} from "node:url";
const root=resolve(dirname(fileURLToPath(import.meta.url)),"..");
export function renderLegacyCompose(source){
 if(typeof source!=="string"||!source.includes("services:"))throw Error("Invalid source Compose configuration");
 const lines=source.split("\n");
 const retained=lines.filter(line=>!/^\s+-\s+\.\/database\/migrations\/0(?:2[5-9]|3[0-3])_[^\n]+:ro\s*$/.test(line));
 if(lines.length-retained.length!==9)throw Error("B8 legacy fixture expected exactly nine omitted migrations");
 return retained.join("\n");
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.env.GITHUB_ACTIONS!=="true"||process.env.CI!=="true")
  throw Error("B8 legacy Compose fixture may only be generated within GitHub Actions");
 const out=resolve(process.argv[2]||"");
 if(process.argv.length!==3||dirname(out)!==root||out===resolve(root,"docker-compose.yml"))
  throw Error("B8 legacy fixture output must be a new sibling of docker-compose.yml");
 const data=renderLegacyCompose(readFileSync(resolve(root,"docker-compose.yml"),"utf8"));
 writeFileSync(out,data,{flag:"wx",mode:0o600});
 process.stdout.write("CI-only legacy Compose fixture generated, nine SecurePay migrations omitted\n");
}
