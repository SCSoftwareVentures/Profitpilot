import {readFileSync,readdirSync} from "node:fs";
import {pathToFileURL} from "node:url";

// CI and local bootstrap must apply every reviewed SQL migration in the
// same order. Reject duplicate sequence numbers and unreviewed init files.
export function verifyMigrationInventory({migrations,init,workflow,compose}){
 const sorted=[...migrations].sort();
 if(!sorted.length||sorted.some((p,i)=>!/^\d{3}_[a-z0-9_]+\.sql$/.test(p)||Number(p.slice(0,3))!==i+2))
  throw new Error("Migration sequence is missing, duplicate or noncanonical");
 if([...init].sort().join(",")!=="002-runtime-role.sql,003-tenant-context-key.sql")throw new Error("Review all database initialization files");
 const expected=["database/schema.sql","database/init/002-runtime-role.sql","database/migrations/"+sorted[0],"database/init/003-tenant-context-key.sql",...sorted.slice(1).map(p=>"database/migrations/"+p)];
 const ci=[...workflow.matchAll(/(?:^|\s)-f (database\/(?:schema\.sql|(?:init|migrations)\/[a-z0-9_.-]+\.sql))(?=\s|$)/gm)].map(m=>m[1]);
 const mounts=[...compose.matchAll(/^\s*-\s+\.\/(database\/(?:schema\.sql|(?:init|migrations)\/[a-z0-9_.-]+\.sql)):\/docker-entrypoint-initdb\.d\/(\d{3})-[a-z0-9-]+\.sql:ro\s*$/gm)];
 if(ci.length!==expected.length||ci.some((p,i)=>p!==expected[i]))throw new Error("CI database migration inventory differs from reviewed sequence");
 if(mounts.length!==expected.length||mounts.some((m,i)=>m[1]!==expected[i]||Number(m[2])!==i+1))throw new Error("Local database migration inventory differs from CI");
 // No additional init-directory mounts can silently load unreviewed SQL.
 if((compose.match(/:\/docker-entrypoint-initdb\.d(?:\/|:)/g)||[]).length!==mounts.length)throw new Error("Unexpected database initialization mount");
 return expected.length;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try{
  const count=verifyMigrationInventory({
   migrations:readdirSync("database/migrations"),init:readdirSync("database/init"),
   workflow:readFileSync(".github/workflows/ci.yml","utf8"),compose:readFileSync("docker-compose.yml","utf8")
  });
  process.stdout.write("Reviewed database bootstrap steps: "+count+"\n");
 }catch(e){process.stderr.write("Migration inventory verification failed: "+e.message+"\n");process.exitCode=1;}
}
