import assert from "node:assert/strict";
import {execFile} from "node:child_process";
import {randomBytes,randomUUID} from "node:crypto";
import {once} from "node:events";
import {createServer} from "node:http";
import test from "node:test";
import {setTimeout as delay} from "node:timers/promises";
import {promisify} from "node:util";
import {exportJWK,generateKeyPair,SignJWT} from "jose";
import pg from "pg";

const container=process.env.TEST_POSTGRES_CONTAINER;
const run=promisify(execFile);
const fingerprintQuery="SELECT system_identifier::text FROM pg_control_system()";

function docker(...args){
  return run("docker",args,{timeout:15_000});
}

async function withAdmin(fn){
  const admin=new pg.Client({connectionString:process.env.TEST_ADMIN_DATABASE_URL,connectionTimeoutMillis:5_000});
  try{
    await admin.connect();
    return await fn(admin);
  }finally{
    await admin.end();
  }
}

test("the same API recovers after a PostgreSQL restart and rolls back interrupted writes",
     {skip:!container,timeout:75_000},async()=>{
  assert.match(container,/^[a-f0-9]{64}$/,"use the full ID of a disposable PostgreSQL container");
  assert.ok(process.env.TEST_ADMIN_DATABASE_URL && process.env.TEST_APP_DATABASE_URL,
    "the restart test requires both the admin and restricted runtime URLs");
  const fingerprint=await withAdmin(async admin=>(await admin.query(fingerprintQuery)).rows[0].system_identifier);
  const {stdout}=await docker("exec",container,"sh","-ec",
    'PGPASSWORD="$POSTGRES_PASSWORD" exec psql -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atqc "$1"',
    "psql",fingerprintQuery);
  assert.equal(stdout.trim(),fingerprint,"the target container must be the configured test database");

  const [tenant,foreignTenant,user,foreignUser,foreignRequest,firstWrite,secondWrite,recoveredWrite]=
    Array.from({length:8},()=>randomUUID());
  const subject="ci-restart-"+user;
  const keyId="ci-restart-"+randomUUID();
  const signingKey=randomBytes(32).toString("hex");
  await withAdmin(async admin=>{
    // The authenticated API suite can revoke its own key during rotation tests.
    await admin.query("INSERT INTO private.tenant_context_keys(key_id,secret,active) VALUES ($1,decode($2,'hex'),true)",
      [keyId,signingKey]);
    await admin.query("INSERT INTO tenants(id,legal_name) VALUES ($1,'CI restart tenant'),($2,'CI restart foreign tenant')",
      [tenant,foreignTenant]);
    await admin.query("INSERT INTO users(id,auth_subject,email,status) VALUES ($1,$2,$3,'active'),($4,$5,$6,'active')",
      [user,subject,user+"@example.invalid",foreignUser,"ci-restart-"+foreignUser,foreignUser+"@example.invalid"]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'analyst','active'),($3,$4,'analyst','active')",
      [tenant,user,foreignTenant,foreignUser]);
    await admin.query("INSERT INTO privacy_requests(tenant_id,requester_id,client_request_id,request_type) VALUES ($1,$2,$3,'access')",
      [foreignTenant,foreignUser,foreignRequest]);
  });

  const issuer="https://profitpilot-ci.invalid/";
  const audience="profitpilot-api";
  const {publicKey,privateKey}=await generateKeyPair("RS256");
  const jwk={...await exportJWK(publicKey),kid:"ci-restart",use:"sig",alg:"RS256"};
  function jwks(req,res){
    res.writeHead(200,{"content-type":"application/json"});
    res.end(JSON.stringify({keys:[jwk]}));
  }
  let app;
  const server=createServer((req,res)=>{
    if(req.url==="/.well-known/jwks.json")jwks(req,res);
    else app(req,res);
  });
  const callbackGate=Promise.withResolvers();
  let pool,interrupted,restartPending=false;
  try{
    server.listen(0,"127.0.0.1");
    await once(server,"listening");
    const base=`http://127.0.0.1:${server.address().port}`;
    Object.assign(process.env,{
      NODE_ENV:"test",PROFITPILOT_PROFILE:"prototype",DATABASE_URL:process.env.TEST_APP_DATABASE_URL,
      DATABASE_SSL:"false",AUTH_ISSUER:issuer,AUTH_AUDIENCE:audience,AUTH_JWKS_URL:base+"/.well-known/jwks.json",
      TENANT_CONTEXT_HMAC_KEY_ID:keyId,TENANT_CONTEXT_HMAC_SECRET:signingKey
    });
    const database=await import("../server/db.js");
    pool=database.pool;
    ({default:app}=await import("../server/index.js"));

    const token=await new SignJWT({}).setProtectedHeader({alg:"RS256",kid:jwk.kid})
      .setIssuer(issuer).setAudience(audience).setSubject(subject).setIssuedAt().setExpirationTime("5m").sign(privateKey);
    const headers={authorization:"Bearer "+token};
    const request=(path,options)=>fetch(base+path,{signal:AbortSignal.timeout(7_000),...options});
    const privacyPath=id=>`/v1/tenants/${id}/privacy-requests`;
    const initial=await request("/health");
    assert.equal(initial.status,200);
    assert.deepEqual(await initial.json(),{status:"ok",database:"connected"});
    const authorized=await request(privacyPath(tenant),{headers});
    assert.equal(authorized.status,200);
    await authorized.json();

    const inserted=Promise.withResolvers();
    let attempts=0;
    interrupted=database.withTenant(tenant,subject,async client=>{
      attempts++;
      const {rowCount}=await client.query(
        "INSERT INTO privacy_requests(tenant_id,requester_id,client_request_id,request_type) VALUES ($1,private.actor_id(),$2,'access'),($1,private.actor_id(),$3,'erasure')",
        [tenant,firstWrite,secondWrite]);
      assert.equal(rowCount,2);
      // Observe the disconnect without attaching an 'error' listener to the client under test.
      const disconnected=new Promise(resolve=>client.once("end",resolve));
      inserted.resolve({disconnected});
      await callbackGate.promise;
    }).then(()=>({error:null}),error=>({error}));
    const {disconnected}=await Promise.race([
      inserted.promise,
      interrupted.then(({error})=>{throw error||new Error("transaction ended before the restart");})
    ]);

    const warm=await request("/health");
    assert.equal(warm.status,200);
    await warm.json();
    assert.ok(pool.idleCount>0,"the restart must also sever an idle pooled connection");

    restartPending=true;
    await docker("stop","--timeout","10",container);
    const unavailable=await request("/health");
    assert.equal(unavailable.status,503);
    assert.deepEqual(await unavailable.json(),{status:"unavailable"});
    await Promise.race([
      disconnected,
      delay(5_000,undefined,{ref:false}).then(()=>assert.fail("the checked-out client did not disconnect"))
    ]);
    callbackGate.resolve();
    const {error}=await interrupted;
    assert.ok(error,"a disconnected transaction must report failure");

    await docker("start",container);
    restartPending=false;
    let status,health;
    for(let attempt=0;attempt<20;attempt++){
      const response=await request("/health");
      status=response.status;
      health=await response.json();
      if(status===200)break;
      await delay(250);
    }
    assert.equal(status,200,"the original HTTP server must become ready again");
    assert.deepEqual(health,{status:"ok",database:"connected"});
    assert.equal(attempts,1,"the interrupted callback must never be replayed");

    const created=await request(privacyPath(tenant),{
      method:"POST",headers:{...headers,"content-type":"application/json"},
      body:JSON.stringify({clientRequestId:recoveredWrite,requestType:"access"})
    });
    assert.equal(created.status,201);
    const recoveredItem=(await created.json()).item;
    const own=await request(privacyPath(tenant),{headers});
    assert.equal(own.status,200);
    assert.deepEqual((await own.json()).items.map(item=>item.id),[recoveredItem.id]);
    const foreign=await request(privacyPath(foreignTenant),{headers});
    assert.equal(foreign.status,403);
    await foreign.json();
    const unsigned=await pool.query("SELECT id FROM privacy_requests WHERE client_request_id IN ($1,$2)",[foreignRequest,recoveredWrite]);
    assert.equal(unsigned.rowCount,0,"an unsigned pooled connection must see neither tenant's rows");
    await withAdmin(async admin=>{
      const {rows}=await admin.query(
        "SELECT client_request_id FROM privacy_requests WHERE client_request_id IN ($1,$2,$3)",
        [firstWrite,secondWrite,recoveredWrite]);
      assert.deepEqual(rows,[{client_request_id:recoveredWrite}],"only the successful post-restart write may persist");
    });
  }finally{
    callbackGate.resolve();
    try{
      if(restartPending)await docker("start",container);
    }finally{
      if(interrupted)await interrupted;
      await pool?.end();
      if(server.listening)await new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()));
    }
  }
});
