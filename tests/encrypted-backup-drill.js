// CI only: encrypt a real ephemeral pg_dump and open it for the isolated restore.
import {randomBytes} from "node:crypto";
import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import pg from "pg";
import {signCheckpoint,checkpointDigest} from "../scripts/privacy-restore-checkpoint.js";
import {sealFile,openFile} from "../scripts/encrypted-pg-backup.js";
if(process.env.PRIVACY_RESTORE_CI!=="1"||process.env.GITHUB_ACTIONS!=="true")throw Error("Isolated CI required");
const url=new URL(process.env.TEST_ADMIN_DATABASE_URL);
if(url.hostname!=="localhost"||url.pathname!=="/profitpilot")throw Error("Unexpected CI database");
const client=new pg.Client({connectionString:url.href,ssl:false});
await client.connect();
try{
 const state=(await client.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
 const checkpoint=signCheckpoint(state,{key:randomBytes(32).toString("hex"),deploymentId:"isolated-ci"});
 const options={key:randomBytes(32).toString("hex"),deploymentId:"isolated-ci",backupId:"current-ci-dump",checkpointSha256:checkpointDigest(checkpoint)};
 const [source,sealed,restored]=process.argv.slice(2);
 await sealFile(source,sealed,options);await openFile(sealed,restored,options);
 assert.deepEqual(await readFile(restored),await readFile(source));
 console.log("Actual PostgreSQL custom-format backup encrypted and authenticated before isolated restore.");
}finally{await client.end();}
