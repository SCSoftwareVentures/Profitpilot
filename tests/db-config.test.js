import test from "node:test";
import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";

function importDatabase({nodeEnv, databaseSsl, suffix="", tlsOverride=""}) {
  return spawnSync(process.execPath, ["--input-type=module", "-e", "await import('./server/db.js')"], {
    cwd: process.cwd(),
    env: {
      ...process.env,
      NODE_ENV: nodeEnv,
      DATABASE_SSL: databaseSsl,
      DATABASE_URL: "postgresql://profitpilot:ci-placeholder@127.0.0.1:5432/profitpilot"+suffix,
      NODE_TLS_REJECT_UNAUTHORIZED: tlsOverride
    },
    encoding: "utf8"
  });
}

test("production database configuration refuses plaintext PostgreSQL connections", () => {
  const result = importDatabase({nodeEnv: "production", databaseSsl: "false"});
  assert.notEqual(result.status, 0, "production startup must fail when database TLS is disabled");
  assert.match(result.stderr, /DATABASE_SSL=true is required in production/);
});

test("production database configuration accepts certificate-verified TLS settings", () => {
  const result = importDatabase({nodeEnv: "production", databaseSsl: "true"});
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("non-production database configuration may use local plaintext PostgreSQL", () => {
  const result = importDatabase({nodeEnv: "test", databaseSsl: "false"});
  assert.equal(result.status, 0, result.stderr || result.stdout);
});

test("TLS configuration refuses connection URL overrides and disabled global verification",()=>{
 for(const suffix of ["?sslmode=disable","?sslmode=no-verify","?sslrootcert=untrusted.pem","?ssl=false","?host=other.example","?options=-c%20search_path%3Dpublic"]){
  const r=importDatabase({nodeEnv:"production",databaseSsl:"true",suffix});
  assert.notEqual(r.status,0);assert.match(r.stderr,/must not contain query parameters/);
 }
 const r=importDatabase({nodeEnv:"production",databaseSsl:"true",tlsOverride:"0"});
 assert.notEqual(r.status,0);assert.match(r.stderr,/certificate verification must not be disabled/);
});
