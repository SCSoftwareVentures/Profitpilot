// CI only: verify actual pg_dump/pg_restore copies; never run against production.
import assert from "node:assert/strict";
import pg from "pg";
import {signCheckpoint,verifyCheckpoint,checkpointDigest} from "../scripts/privacy-restore-checkpoint.js";
if(process.env.PRIVACY_RESTORE_CI!=="1"||process.env.GITHUB_ACTIONS!=="true")throw Error("Isolated GitHub CI environment required");
const names=["profitpilot","privacy_restore_old_ci","privacy_restore_new_ci"];
async function state(name){
 if(!names.includes(name))throw Error("Unexpected database");
 const url=new URL(process.env.TEST_ADMIN_DATABASE_URL);
 if(url.hostname!=="localhost"||url.pathname!=="/profitpilot")throw Error("Unexpected CI database");
 url.pathname="/"+name;
 const client=new pg.Client({connectionString:url.href,ssl:false});
 await client.connect();
 try{return (await client.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;}
 finally{await client.end();}
}
const live=await state(names[0]),old=await state(names[1]),fresh=await state(names[2]);
assert.ok(live.markers.some(m=>m.kind==="closure"));
assert.ok(live.markers.some(m=>m.kind==="redaction"));
const revocations=live.markers.filter(m=>m.kind==="account_session_revocation");
assert.ok(revocations.length>=2,"physical recovery drill must cover repeated account revocations");
assert.equal(old.markers.some(m=>m.kind==="account_session_revocation"),false);

const options={key:process.env.PRIVACY_DRILL_KEY,deploymentId:"isolated-ci",now:Date.now()};
const revocationCheckpoint=signCheckpoint({markers:revocations,violations:[]},options);
const revocationVerify={...options,expectedDigest:checkpointDigest(revocationCheckpoint)};
assert.throws(()=>verifyCheckpoint(revocationCheckpoint,old,revocationVerify),/missing or has changed/);
assert.equal(verifyCheckpoint(revocationCheckpoint,fresh,revocationVerify).verified,true);
const individual=live.markers.filter(m=>m.kind==="individual_session_revocation");
assert.ok(individual.length>=1,"physical restore drill must include individually revoked access tokens");
const individualCheckpoint=signCheckpoint({markers:individual,violations:[]},options);
const individualVerify={...options,expectedDigest:checkpointDigest(individualCheckpoint)};
assert.throws(()=>verifyCheckpoint(individualCheckpoint,old,individualVerify),/missing or has changed/);
assert.equal(verifyCheckpoint(individualCheckpoint,fresh,individualVerify).verified,true);
const checkpoint=signCheckpoint(live,options);
const verify={...options,expectedDigest:checkpointDigest(checkpoint)};
assert.throws(()=>verifyCheckpoint(checkpoint,old,verify),/missing or has changed/);
assert.equal(verifyCheckpoint(checkpoint,fresh,verify).verified,true);
assert.deepEqual(fresh,live);
console.log("Actual PostgreSQL backup restore: pre-privacy-action snapshot rejected; current snapshot accepted.");
