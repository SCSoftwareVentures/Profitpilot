import test from "node:test";
import assert from "node:assert/strict";
import {createServer} from "node:http";
import {createHmac,randomBytes} from "node:crypto";
import {generateKeyPair,exportJWK,SignJWT} from "jose";
import pg from "pg";

const enabled=Boolean(process.env.TEST_ADMIN_DATABASE_URL);
test("authenticated API enforces tenant membership, role permissions and import idempotency",{skip:!enabled},async()=>{
  const issuer="https://profitpilot-ci.invalid/";
  const audience="profitpilot-api";
  const tenantA="11111111-1111-4111-8111-111111111111";
  const tenantB="22222222-2222-4222-8222-222222222222";
  const userA="33333333-3333-4333-8333-333333333333";
  const userB="44444444-4444-4444-8444-444444444444";
  const userC="aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const businessA="55555555-5555-4555-8555-555555555555";
  const contractA="66666666-6666-4666-8666-666666666666";
  const businessB="77777777-7777-4777-8777-777777777777";
  const contractB="88888888-8888-4888-8888-888888888888";
  const {publicKey,privateKey}=await generateKeyPair("RS256");
  const jwk=await exportJWK(publicKey);
  jwk.kid="profitpilot-ci-key";
  jwk.use="sig";
  jwk.alg="RS256";
  const jwksServer=createServer((req,res)=>{
    if(req.url!=="/.well-known/jwks.json"){res.writeHead(404).end();return;}
    res.writeHead(200,{"content-type":"application/json","cache-control":"no-store"});
    res.end(JSON.stringify({keys:[jwk]}));
  });
  await new Promise(resolve=>jwksServer.listen(0,"127.0.0.1",resolve));
  const jwksAddress=jwksServer.address();
  process.env.NODE_ENV="test";
  process.env.DATABASE_URL=process.env.TEST_APP_DATABASE_URL;
  process.env.AUTH_ISSUER=issuer;
  process.env.AUTH_AUDIENCE=audience;
  process.env.AUTH_STEP_UP_ACR="urn:profitpilot:step-up";
  process.env.AUTH_JWKS_URL=`http://127.0.0.1:${jwksAddress.port}/.well-known/jwks.json`;
  if(!process.env.TENANT_CONTEXT_HMAC_SECRET)throw new Error("CI tenant context signing key is required");
  const admin=new pg.Pool({connectionString:process.env.TEST_ADMIN_DATABASE_URL});
  const [{default:app},{pool:appPool,withTenant,assertRuntimeDatabaseRole}]=await Promise.all([import("../server/index.js"),import("../server/db.js")]);
  const api=createServer(app);
  await new Promise(resolve=>api.listen(0,"127.0.0.1",resolve));
  const apiAddress=api.address();
  const base=`http://127.0.0.1:${apiAddress.port}`;
  async function token(subject){
    return new SignJWT({email:subject+"@example.invalid",auth_time:Math.floor(Date.now()/1000),acr:"urn:profitpilot:step-up",amr:["pwd","mfa"]})
      .setProtectedHeader({alg:"RS256",kid:jwk.kid})
      .setIssuer(issuer).setAudience(audience).setSubject(subject)
      .setIssuedAt().setExpirationTime("5m").setJti(randomBytes(16).toString("hex")).sign(privateKey);
  }
  async function customToken(subject,{issuedAt=Math.floor(Date.now()/1000),expiresAt=Math.floor(Date.now()/1000)+300,includeIssuedAt=true,includeExpiry=true,authTime,acr,amr,typ,jti=randomBytes(16).toString("hex")}={}){
    const claims={email:subject+"@example.invalid"};if(authTime!==undefined)claims.auth_time=authTime;if(acr!==undefined)claims.acr=acr;if(amr!==undefined)claims.amr=amr;
    let jwt=new SignJWT(claims).setProtectedHeader({alg:"RS256",kid:jwk.kid,...(typ===undefined?{}:{typ})}).setIssuer(issuer).setAudience(audience).setSubject(subject);
    if(includeIssuedAt)jwt=jwt.setIssuedAt(issuedAt);
    if(includeExpiry)jwt=jwt.setExpirationTime(expiresAt);
    jwt=jwt.setJti(jti);
    return jwt.sign(privateKey);
  }
  async function request(path,{subject,method="GET",body}={}){
    const headers={};
    if(subject)headers.authorization="Bearer "+await token(subject);
    if(body!==undefined)headers["content-type"]="application/json";
    return fetch(base+path,{method,headers,body:body===undefined?undefined:JSON.stringify(body)});
  }
  try{
    const userD="bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
    const userE="cccccccc-cccc-4ccc-8ccc-cccccccccccc";
    await admin.query("INSERT INTO users(id,auth_subject,email,status) VALUES ($1,'ci-api-analyst','analyst@example.invalid','active'),($2,'ci-api-reader','reader@example.invalid','active'),($3,'ci-api-tenant-b-only','tenant-b@example.invalid','active'),($4,'ci-api-reviewer','reviewer@example.invalid','active'),($5,'ci-api-owner','owner@example.invalid','active') ON CONFLICT(auth_subject) DO UPDATE SET status='active'",[userA,userB,userC,userD,userE]);
    await admin.query("UPDATE users SET auth_issuer=$1 WHERE id=ANY($2::uuid[]) AND auth_issuer IS NULL",[issuer,[userA,userB,userC,userD,userE]]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'analyst','active'),($1,$3,'read_only','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantA,userA,userB]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'analyst','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantB,userC]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'reviewer','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantA,userD]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES ($1,$2,'owner','active') ON CONFLICT(tenant_id,user_id) DO UPDATE SET role=EXCLUDED.role,status='active'",[tenantA,userE]);
    await admin.query("INSERT INTO businesses(id,tenant_id,name) VALUES ($1,$2,'CI Business A') ON CONFLICT(id) DO NOTHING",[businessA,tenantA]);
    await admin.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'CI Customer A','active') ON CONFLICT(id) DO NOTHING",[contractA,tenantA,businessA]);
    await admin.query("INSERT INTO businesses(id,tenant_id,name) VALUES ($1,$2,'CI Business B') ON CONFLICT(id) DO NOTHING",[businessB,tenantB]);
    await admin.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'CI Customer B','active') ON CONFLICT(id) DO NOTHING",[contractB,tenantB,businessB]);
    await assert.rejects(()=>admin.query("INSERT INTO import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by) VALUES ($1,$2,'payroll','CI permission','uploaded',$3,'cross-tenant.csv',$4)",["bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",tenantA,"d".repeat(64),userC]),/foreign key constraint/i,"a user who belongs only to tenant B must not be recorded as the creator of a tenant A import");

    assert.equal(await assertRuntimeDatabaseRole(),true,"actual production role gate accepts the least-privilege runtime");
    await assert.rejects(()=>appPool.query("CREATE TEMP TABLE shadow_identity(id uuid)"),/permission denied/i);
    await assert.rejects(()=>appPool.query("CREATE TABLE public.shadow_identity(id uuid)"),/permission denied/i);
    const healthResponse=await request("/health");
    assert.equal(healthResponse.headers.get("x-powered-by"),null,"the API must not disclose its Express framework");
    assert.ok(healthResponse.headers.get("x-content-type-options"),"Helmet security headers must be present");
    const savedAudience=process.env.AUTH_AUDIENCE;
    delete process.env.AUTH_AUDIENCE;
    const unavailableAuth=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+await token("ci-api-analyst")}});
    assert.equal(unavailableAuth.status,503,"missing authentication configuration must fail closed as service unavailable");
    process.env.AUTH_AUDIENCE=savedAudience;
    const savedNodeEnv=process.env.NODE_ENV;
    const savedJwksUrl=process.env.AUTH_JWKS_URL;
    process.env.NODE_ENV="production";
    process.env.AUTH_JWKS_URL="http://127.0.0.1/.well-known/jwks.json";
    const insecureJwks=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+await token("ci-api-analyst")}});
    assert.equal(insecureJwks.status,503,"production authentication must reject a non-HTTPS JWKS endpoint");
    process.env.NODE_ENV=savedNodeEnv;
    process.env.AUTH_JWKS_URL=savedJwksUrl;
    const oversizedToken=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+"a".repeat(8193)}});
    assert.equal(oversizedToken.status,401,"oversized bearer tokens must be rejected before remote key verification");
    const trackedSessionToken=await token("ci-api-analyst");
    const trackedSessionResponse=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+trackedSessionToken}});
    assert.equal(trackedSessionResponse.status,200,"valid jti-bearing tokens must register a server-side session");
    // A valid provider signature cannot reuse a JTI with a different token lifetime or subject.
    const now=Math.floor(Date.now()/1000), collisionId=randomBytes(16).toString("hex");
    const collisionClaims={issuedAt:now,expiresAt:now+300,jti:collisionId};
    const original=await customToken("ci-api-analyst",collisionClaims);
    const useToken=async v=>fetch(base+"/v1/me",{headers:{authorization:"Bearer "+v}});
    assert.equal((await useToken(original)).status,200);
    assert.equal((await useToken(await customToken("ci-api-analyst",{...collisionClaims,expiresAt:now+301}))).status,401);
    assert.equal((await useToken(await customToken("ci-api-analyst",{...collisionClaims,issuedAt:now-1}))).status,401);
    assert.equal((await useToken(await customToken("ci-api-owner",collisionClaims))).status,401);
    assert.equal((await useToken(original)).status,200);
    assert.equal((await useToken(await customToken("ci-api-analyst",{expiresAt:now+3600}))).status,401);
    assert.equal((await useToken(await customToken("ci-api-analyst",{jti:"invalid session identifier"}))).status,401);
    await assert.rejects(()=>appPool.query("SELECT private.is_bound_auth_session_revoked($1,$2,$3)",[collisionId,"ci-api-analyst",issuer]),/permission denied/i);
    const revocableSessionToken=await token("ci-api-analyst");
    const revocableSessionResponse=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+revocableSessionToken}});
    assert.equal(revocableSessionResponse.status,200);
    {
     const privileges=(await admin.query("SELECT has_function_privilege('profitpilot_app','private.accept_bound_access_session(text,text,text,timestamptz,timestamptz)','EXECUTE') AS admit,has_function_privilege('profitpilot_app','private.list_auth_sessions(text)','EXECUTE') AS list,has_function_privilege('profitpilot_app','private.revoke_auth_session(text,text,text)','EXECUTE') AS revoke")).rows[0];
     assert.deepEqual(privileges,{admit:false,list:false,revoke:false});
     await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("SELECT private.verified_session_operation($1,$2,$3)",["primary",JSON.stringify({action:"list",subject:"ci-api-owner"}),"0".repeat(64)])),/session attestation/i);
    }
    const sessionListResponse=await fetch(base+"/v1/me/sessions",{headers:{authorization:"Bearer "+trackedSessionToken}});
    assert.equal(sessionListResponse.status,200,"users must be able to inspect their own active and revoked sessions");
    const sessionInventory=await sessionListResponse.json();
    assert.equal(sessionInventory.truncated,false);
    const sessionList=sessionInventory.items;
    assert.ok(sessionList.length>=2,"session inventory must contain registered sessions");
    const sessionPayload=JSON.parse(Buffer.from(revocableSessionToken.split(".")[1],"base64url").toString("utf8"));
    const revokeResponse=await fetch(base+`/v1/me/sessions/${sessionPayload.jti}`,{method:"DELETE",headers:{authorization:"Bearer "+trackedSessionToken}});
    assert.equal(revokeResponse.status,200,"a user must be able to revoke another one of their own sessions");
    const revokedSessionUse=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+revocableSessionToken}});
    assert.equal(revokedSessionUse.status,401,"a revoked access session must be rejected on its next request");
    const singleEvidence=(await admin.query("SELECT id FROM private.individual_session_revocation_receipts WHERE token_fingerprint=public.digest(convert_to($1,'UTF8'),'sha256')",[sessionPayload.jti])).rows[0];
    assert.ok(singleEvidence);
    await assert.rejects(()=>appPool.query("SELECT * FROM private.individual_session_revocation_receipts"),/permission denied/i);
    await assert.rejects(()=>admin.query("DELETE FROM private.individual_session_revocation_receipts WHERE id=$1",[singleEvidence.id]),/immutable/i);
    const singleProbe=await admin.connect();
    try{
     await singleProbe.query("BEGIN");
     await singleProbe.query("UPDATE private.auth_sessions SET revoked_at=NULL,revocation_reason=NULL WHERE jti=$1",[sessionPayload.jti]);
     const inconsistent=(await singleProbe.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
     assert.ok(inconsistent.violations.some(v=>v.kind==="individually_revoked_session_reinstated"&&v.id===singleEvidence.id));
     await singleProbe.query("DELETE FROM private.auth_sessions WHERE jti=$1",[sessionPayload.jti]);
     const denied=(await singleProbe.query("SELECT private.accept_bound_access_session($1,$2,$3,to_timestamp($4),to_timestamp($5)) AS allowed",[sessionPayload.jti,sessionPayload.sub,sessionPayload.iss,sessionPayload.iat,sessionPayload.exp])).rows[0];
     assert.equal(denied.allowed,false,"a missing session row must not bypass an independent revocation receipt");
    }finally{await singleProbe.query("ROLLBACK");singleProbe.release();}
    const singleState=(await admin.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
    assert.ok(singleState.markers.some(m=>m.kind==="individual_session_revocation"&&m.id===singleEvidence.id));
    assert.equal(JSON.stringify(singleState.markers).includes(sessionPayload.jti),false);

    // Isolated identity: exercise a security incident without breaking the other fixtures.
    const incidentSubject="ci-api-incident";
    await admin.query("INSERT INTO users(id,auth_subject,email,status,auth_issuer) VALUES ($1,$2,'incident@example.invalid','active',$3)",["deadbeef-1111-4111-8111-111111111111",incidentSubject,issuer]);
    const incidentToken=await token(incidentSubject), oldEventToken=await token(incidentSubject);
    const incidentHeaders={authorization:"Bearer "+incidentToken,"content-type":"application/json"};
    const revokeAll=body=>fetch(base+"/v1/me/sessions/revoke-all",{method:"POST",headers:incidentHeaders,body:JSON.stringify(body)});
    assert.equal((await useToken(oldEventToken)).status,200);
    assert.equal((await revokeAll({confirm:false})).status,400);
    const noMfa=await customToken(incidentSubject);
    assert.equal((await fetch(base+"/v1/me/sessions/revoke-all",{method:"POST",headers:{authorization:"Bearer "+noMfa,"content-type":"application/json"},body:JSON.stringify({confirm:true})})).status,403);
    const allResponse=await revokeAll({confirm:true});
    assert.equal(allResponse.status,200);
    const allResult=await allResponse.json();
    assert.ok(allResult.revokedCount>=2);
    assert.equal(allResult.providerRevocationConfirmed,false);
    assert.equal((await useToken(incidentToken)).status,401);
    assert.equal((await useToken(oldEventToken)).status,401);
    const cutoff=allResult.revokedThroughEpoch;
    assert.equal((await useToken(await customToken(incidentSubject,{authTime:cutoff}))).status,401);
    assert.equal((await useToken(await customToken(incidentSubject))).status,401);
    await new Promise(resolve=>setTimeout(resolve,1100));
    assert.equal((await useToken(await token(incidentSubject))).status,200);
    assert.equal((await useToken(await customToken(incidentSubject,{authTime:cutoff}))).status,401,"refresh-derived tokens with old authentication must remain rejected");
    await assert.rejects(()=>appPool.query("SELECT * FROM private.account_session_revocations"),/permission denied/i);
    await assert.rejects(()=>appPool.query("SELECT * FROM private.account_session_revocation_receipts"),/permission denied/i);
    const incidentId="deadbeef-1111-4111-8111-111111111111";
    const firstRevocationState=(await admin.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
    const firstReceipt=firstRevocationState.markers.find(m=>m.kind==="account_session_revocation"&&m.userId===incidentId);
    assert.ok(firstReceipt);
    const secondToken=await token(incidentSubject);
    const secondResponse=await fetch(base+"/v1/me/sessions/revoke-all",{method:"POST",headers:{authorization:"Bearer "+secondToken,"content-type":"application/json"},body:JSON.stringify({confirm:true})});
    assert.equal(secondResponse.status,200);
    const secondResult=await secondResponse.json();
    assert.ok(secondResult.revokedThroughEpoch>cutoff);
    const secondRevocationState=(await admin.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
    const receipts=secondRevocationState.markers.filter(m=>m.kind==="account_session_revocation"&&m.userId===incidentId);
    assert.equal(receipts.length,2);
    assert.ok(receipts.some(m=>m.id===firstReceipt.id));
    assert.deepEqual(secondRevocationState.violations,[]);
    await assert.rejects(()=>admin.query("UPDATE private.account_session_revocations SET revoked_through_epoch=$2 WHERE user_id=$1",[incidentId,cutoff]),/cannot regress/i);
    await assert.rejects(()=>admin.query("DELETE FROM private.account_session_revocations WHERE user_id=$1",[incidentId]),/must be retained/i);
    await assert.rejects(()=>admin.query("DELETE FROM private.account_session_revocation_receipts WHERE user_id=$1",[incidentId]),/immutable/i);
    const probe=await admin.connect();
    try{
     await probe.query("BEGIN");
     await probe.query("UPDATE private.auth_sessions SET revoked_at=NULL,revocation_reason=NULL WHERE subject=$1 AND issued_at<=to_timestamp($2)",[incidentSubject,cutoff]);
     const inconsistent=(await probe.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
     assert.ok(inconsistent.violations.some(v=>v.kind==="revoked_session_reinstated"&&v.id===incidentId));
    }finally{await probe.query("ROLLBACK");probe.release();}

    // Exercise separation of duties with actual SQL session identities (CI superuser fixture only).
    const compromiseId="deadbeef-2222-4222-8222-222222222222",compromiseSubject="ci-api-compromise";
    await admin.query("INSERT INTO users(id,auth_subject,email,status,auth_issuer) VALUES($1,$2,'compromise@example.invalid','active',$3)",[compromiseId,compromiseSubject,issuer]);
    await admin.query("INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES($1,$2,'analyst','active')",[tenantA,compromiseId]);
    const compromisedToken=await token(compromiseSubject);
    assert.equal((await useToken(compromisedToken)).status,200);
    await admin.query("CREATE ROLE ci_containment_operator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; CREATE ROLE ci_recovery_operator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE; GRANT profitpilot_incident_containment TO ci_containment_operator; GRANT profitpilot_incident_recovery TO ci_recovery_operator");
    let incidentCase;
    const operatorClient=await admin.connect();
    try{
     await operatorClient.query("SET SESSION AUTHORIZATION ci_containment_operator");
     incidentCase=(await operatorClient.query("SELECT private.contain_compromised_account($1,$2) AS id",[compromiseId,"a".repeat(64)])).rows[0].id;
     await assert.rejects(()=>operatorClient.query("SELECT private.recover_contained_account($1,$2,$3)",[incidentCase,"b".repeat(64),"c".repeat(64)]),/permission denied/i);
     await operatorClient.query("RESET SESSION AUTHORIZATION");
     assert.equal((await useToken(compromisedToken)).status,401);
     assert.equal((await useToken(await token(compromiseSubject))).status,401,"new provider authentication cannot bypass local containment");
     await assert.rejects(()=>admin.query("UPDATE users SET status='active' WHERE id=$1",[compromiseId]),/independent recovery/i);
     await assert.rejects(()=>appPool.query("SELECT private.recover_contained_account($1,$2,$3)",[incidentCase,"b".repeat(64),"c".repeat(64)]),/permission denied/i);
     await assert.rejects(()=>appPool.query("SELECT * FROM private.account_security_incidents"),/permission denied/i);
     assert.equal((await withTenant(tenantA,compromiseSubject,c=>c.query("SELECT private.current_tenant_id() AS tenant"))).rows[0].tenant,null);
     await operatorClient.query("SET SESSION AUTHORIZATION ci_recovery_operator");
     await assert.rejects(()=>operatorClient.query("SELECT private.recover_contained_account($1,$2,$3)",[incidentCase,"b".repeat(64),"b".repeat(64)]),/Separate identity/i);
     await assert.rejects(()=>operatorClient.query("SELECT private.recover_contained_account($1,$2,$3)",[incidentCase,"a".repeat(64),"c".repeat(64)]),/new evidence/i);
     assert.equal((await operatorClient.query("SELECT private.recover_contained_account($1,$2,$3) AS ok",[incidentCase,"b".repeat(64),"c".repeat(64)])).rows[0].ok,true);
     await assert.rejects(()=>operatorClient.query("SELECT private.recover_contained_account($1,$2,$3)",[incidentCase,"b".repeat(64),"c".repeat(64)]),/Recoverable contained account/i);
     await operatorClient.query("RESET SESSION AUTHORIZATION");
    }finally{await operatorClient.query("RESET SESSION AUTHORIZATION");operatorClient.release();}
    await admin.query("DROP ROLE ci_containment_operator; DROP ROLE ci_recovery_operator");
    assert.equal((await useToken(compromisedToken)).status,401);
    await new Promise(resolve=>setTimeout(resolve,1100));
    assert.equal((await useToken(await token(compromiseSubject))).status,200);
    const incidentState=(await admin.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
    assert.ok(incidentState.markers.some(m=>m.kind==="account_contained"&&m.id===incidentCase));
    assert.ok(incidentState.markers.some(m=>m.kind==="account_recovered"&&m.id===incidentCase));
    assert.deepEqual(incidentState.violations,[]);

    process.env.AUTH_REQUIRE_ACCESS_TOKEN_TYPE="true";
    try{
     for(const typ of [undefined,"JWT","id+jwt","refresh+jwt"]){
      assert.equal((await useToken(await customToken("ci-api-analyst",{typ}))).status,401,"non-access JWT type rejected");
     }
     for(const typ of ["at+jwt","application/at+jwt"]){
      assert.equal((await useToken(await customToken("ci-api-analyst",{typ}))).status,200);
     }
    }finally{delete process.env.AUTH_REQUIRE_ACCESS_TOKEN_TYPE;}
    const noToken=await request("/v1/me");
    assert.equal(noToken.status,401,"requests without a bearer token must be rejected");
    const noExpiry=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+await customToken("ci-api-analyst",{includeExpiry:false})}});
    assert.equal(noExpiry.status,401,"JWTs without an expiry claim must be rejected");
    const staleToken=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+await customToken("ci-api-analyst",{issuedAt:Math.floor(Date.now()/1000)-3600,expiresAt:Math.floor(Date.now()/1000)+60})}});
    assert.equal(staleToken.status,401,"access tokens older than the configured maximum age must be rejected");
    const expiredToken=await fetch(base+"/v1/me",{headers:{authorization:"Bearer "+await customToken("ci-api-analyst",{issuedAt:Math.floor(Date.now()/1000)-600,expiresAt:Math.floor(Date.now()/1000)-30})}});
    assert.equal(expiredToken.status,401,"expired access tokens must be rejected");

    assert.equal(noToken.headers.get("cache-control"),"no-store","unauthenticated API responses must not be cached");
    const malformed=await fetch(base+"/v1/me",{method:"POST",headers:{"content-type":"application/json"},body:"{"});
    assert.equal(malformed.status,400,"malformed JSON must be rejected");
    assert.equal((await malformed.json()).error,"Invalid request","parser details must not be exposed to clients");

    const own=await request(`/v1/tenants/${tenantA}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(own.status,200);
    const ownBody=await own.json();
    assert.equal(ownBody.items.length,1);
    assert.equal(ownBody.items[0].id,contractA);
    const scopedRows=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM contracts ORDER BY id"));
    assert.deepEqual(scopedRows.rows.map(row=>row.id),[contractA],"database RLS must hide tenant B contract rows even from a tenant A scoped connection");
    const ownIdentityRows=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT auth_subject FROM users ORDER BY auth_subject"));
    assert.deepEqual(ownIdentityRows.rows.map(row=>row.auth_subject),["ci-api-analyst"],"a signed subject may read only its own global identity row");
    const unscopedIdentityRows=await appPool.query("SELECT auth_subject FROM users");
    assert.equal(unscopedIdentityRows.rowCount,0,"the runtime role must not enumerate global identities without signed context");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("UPDATE users SET email='changed@example.invalid' WHERE auth_subject='ci-api-analyst'")),/permission denied/i,"the runtime role must not update identity records");
    const rawClient=await appPool.connect();
    try{
      await rawClient.query("BEGIN");
      await rawClient.query("SELECT set_config('app.tenant_id',$1,true)",[tenantB]);
      const forged=await rawClient.query("SELECT id FROM contracts");
      assert.equal(forged.rowCount,0,"a raw custom GUC must not grant tenant access without a valid server HMAC");
      await rawClient.query("ROLLBACK");
    }finally{rawClient.release();}
    async function assertContextDenied({tenantId,subject,expires,nonce,signatureOverride}){
      const keyId="primary";
      const client=await appPool.connect();
      try{
        await client.query("BEGIN");
        const {rows:[ctx]}=await client.query("SELECT txid_current()::text AS tx,pg_backend_pid()::text AS pid");
        const payload=["profitpilot-tenant-context-v2",ctx.tx,ctx.pid,tenantId,subject,expires,nonce,keyId].join("\n");
        const signature=signatureOverride||createHmac("sha256",Buffer.from(process.env.TENANT_CONTEXT_HMAC_SECRET,"hex")).update(payload).digest("hex");
        await client.query("SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)",[tenantId,subject,expires,nonce,keyId,signature]);
        const result=await client.query("SELECT id FROM contracts");
        assert.equal(result.rowCount,0,"invalid tenant context must return no protected rows");
        await client.query("ROLLBACK");
      }finally{client.release();}
    }
    const contextFields=["app.tenant_id","app.tenant_subject","app.tenant_expires","app.tenant_nonce","app.tenant_key_id","app.tenant_signature"];
    const contextSet="SELECT set_config('app.tenant_id',$1,true),set_config('app.tenant_subject',$2,true),set_config('app.tenant_expires',$3,true),set_config('app.tenant_nonce',$4,true),set_config('app.tenant_key_id',$5,true),set_config('app.tenant_signature',$6,true)";
    const replayClient=await appPool.connect(),otherClient=await appPool.connect();
    try{
     await replayClient.query("BEGIN");
     const {rows:[ctx]}=await replayClient.query("SELECT txid_current()::text AS tx,pg_backend_pid()::text AS pid");
     const fields=[tenantA,"ci-api-analyst",String(Math.floor(Date.now()/1000)+30),randomBytes(16).toString("hex"),"primary"];
     const proof=createHmac("sha256",Buffer.from(process.env.TENANT_CONTEXT_HMAC_SECRET,"hex")).update(["profitpilot-tenant-context-v2",ctx.tx,ctx.pid,...fields].join("\n")).digest("hex");
     const copied=[...fields,proof];
     assert.equal(contextFields.length,copied.length);
     await replayClient.query(contextSet,copied);
     assert.equal((await replayClient.query("SELECT id FROM contracts")).rowCount,1,"valid transaction-bound context reads own tenant");
     await otherClient.query("BEGIN");
     await otherClient.query(contextSet,copied);
     assert.equal((await otherClient.query("SELECT id FROM contracts")).rowCount,0,"captured signature must fail on another PostgreSQL backend");
     await otherClient.query("ROLLBACK");
     await replayClient.query("COMMIT");
     await replayClient.query("BEGIN");
     await replayClient.query(contextSet,copied);
     assert.equal((await replayClient.query("SELECT id FROM contracts")).rowCount,0,"captured signature must fail in a new transaction on same backend");
     const legacyProof=createHmac("sha256",Buffer.from(process.env.TENANT_CONTEXT_HMAC_SECRET,"hex")).update(fields.join("\n")).digest("hex");
     await replayClient.query(contextSet,[...fields,legacyProof]);
     assert.equal((await replayClient.query("SELECT id FROM contracts")).rowCount,0,"legacy replayable context format must not remain valid");
    }finally{
     await Promise.all([replayClient.query("ROLLBACK"),otherClient.query("ROLLBACK")]);
     replayClient.release();otherClient.release();
    }
    const readOnlyContext=await withTenant(tenantA,"ci-api-analyst",c=>c.query("SELECT id FROM contracts"),{repeatableRead:true});
    assert.equal(readOnlyContext.rowCount,1,"transaction context must work in read-only repeatable-read transactions");
    const future=String(Math.floor(Date.now()/1000)+30);
    const past=String(Math.floor(Date.now()/1000)-5);
    await assertContextDenied({tenantId:tenantA,subject:"ci-api-analyst",expires:future,nonce:randomBytes(16).toString("hex"),signatureOverride:"0".repeat(64)});
    await assertContextDenied({tenantId:tenantA,subject:"ci-api-analyst",expires:past,nonce:randomBytes(16).toString("hex")});
    await assertContextDenied({tenantId:tenantA,subject:"ci-api-nonmember",expires:future,nonce:randomBytes(16).toString("hex")});
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT secret FROM private.tenant_context_keys")),/permission denied/i,"runtime role must not read the tenant signing key");
    const roleAudit=await admin.query("SELECT rolbypassrls,rolsuper,rolcanlogin FROM pg_roles WHERE rolname='profitpilot_app'");
    assert.deepEqual(roleAudit.rows[0],{rolbypassrls:false,rolsuper:false,rolcanlogin:true},"runtime role must remain login-capable but must not bypass RLS or be superuser");
    const primarySecret=process.env.TENANT_CONTEXT_HMAC_SECRET;
    const primaryKeyId=process.env.TENANT_CONTEXT_HMAC_KEY_ID||"primary";
    const secondarySecret=randomBytes(32).toString("hex");
    await admin.query("INSERT INTO private.tenant_context_keys(key_id,secret,active) VALUES ('rotation-next',decode($1,'hex'),true)",[secondarySecret]);
    await assert.rejects(()=>admin.query("INSERT INTO private.tenant_context_keys(key_id,secret,active) VALUES ('rotation-duplicate',decode($1,'hex'),true)",[primarySecret]),/duplicate key/i,"existing signing material must not be registered under another identifier");
    await assert.rejects(()=>admin.query("UPDATE private.tenant_context_keys SET secret=decode($1,'hex') WHERE key_id=$2",[secondarySecret,primaryKeyId]),/only transition once/i,"active signing material cannot be replaced in place");
    const primaryDuringOverlap=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM contracts"));
    assert.equal(primaryDuringOverlap.rowCount,1,"the original key must remain valid during the overlap window");
    process.env.TENANT_CONTEXT_HMAC_SECRET=secondarySecret;
    process.env.TENANT_CONTEXT_HMAC_KEY_ID="rotation-next";
    const secondaryDuringOverlap=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM contracts"));
    assert.equal(secondaryDuringOverlap.rowCount,1,"the replacement key must work before revoking the original");
    await admin.query("UPDATE private.tenant_context_keys SET active=false WHERE key_id=$1",[primaryKeyId]);
    const tombstone=(await admin.query("SELECT active,secret IS NULL AS secret_removed,revoked_at IS NOT NULL AS recorded FROM private.tenant_context_keys WHERE key_id=$1",[primaryKeyId])).rows[0];
    assert.deepEqual(tombstone,{active:false,secret_removed:true,recorded:true});
    await assert.rejects(()=>admin.query("UPDATE private.tenant_context_keys SET active=true WHERE key_id=$1",[primaryKeyId]),/only transition once/i);
    await assert.rejects(()=>admin.query("DELETE FROM private.tenant_context_keys WHERE key_id=$1",[primaryKeyId]),/tombstones/i);
    await assert.rejects(()=>admin.query("INSERT INTO private.tenant_context_keys(key_id,secret,active) VALUES ('rotation-retired',decode($1,'hex'),true)",[primarySecret]),/duplicate key/i);
    process.env.TENANT_CONTEXT_HMAC_SECRET=primarySecret;
    process.env.TENANT_CONTEXT_HMAC_KEY_ID=primaryKeyId;
    const revokedPrimary=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM contracts"));
    assert.equal(revokedPrimary.rowCount,0,"a revoked signing key must no longer authorise tenant rows");
    process.env.TENANT_CONTEXT_HMAC_SECRET=secondarySecret;
    process.env.TENANT_CONTEXT_HMAC_KEY_ID="rotation-next";
    const activeSecondary=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM contracts"));
    assert.equal(activeSecondary.rowCount,1,"the replacement key must remain valid after old-key revocation");
    const afterCommit=await appPool.query("SELECT current_setting('app.tenant_id',true) AS tenant_id");
    assert.ok(afterCommit.rows[0].tenant_id===null||afterCommit.rows[0].tenant_id==="","tenant context must not leak after a transaction returns its pooled connection");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES ($1,$2,$3,'RLS write probe','active')",["99999999-9999-4999-8999-999999999999",tenantB,businessB])),/row-level security/i,"RLS WITH CHECK must reject cross-tenant writes");

    const otherTenant=await request(`/v1/tenants/${tenantB}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(otherTenant.status,403,"a tenant A member must not access tenant B");

    const invalidTenant=await request("/v1/tenants/not-a-uuid/contracts",{subject:"ci-api-analyst"});
    assert.equal(invalidTenant.status,400);

    const invalidDate=await request(`/v1/tenants/${tenantA}/imports`,{
      subject:"ci-api-analyst",method:"POST",
      body:{sourceType:"payroll",fileName:"payroll.csv",sha256:"a".repeat(64),permissionReference:"CI permission",periodStart:"2026-02-31",periodEnd:"2026-03-01"}
    });
    assert.equal(invalidDate.status,400,"impossible calendar dates must be rejected");

    const importBody={sourceType:"payroll",fileName:"payroll.csv",sha256:"b".repeat(64),permissionReference:"CI permission",periodStart:"2026-02-01",periodEnd:"2026-02-28",tenantId:tenantB};
    const created=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:importBody});
    assert.equal(created.status,201);
    const createdBody=await created.json();
    const storedBatch=await admin.query("SELECT tenant_id FROM import_batches WHERE id=$1",[createdBody.batch.id]);
    assert.equal(storedBatch.rows[0].tenant_id,tenantA,"client-supplied tenant identifiers must not override the authenticated path tenant");
    const duplicate=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-analyst",method:"POST",body:importBody});
    assert.equal(duplicate.status,200);
    assert.equal((await duplicate.json()).idempotent,true);
    for(const patch of [{sourceType:"supplier_invoice"},{periodEnd:"2026-02-27"},{permissionReference:"Different permission"},{fileName:"different.csv"}]){
     const changed=await request("/v1/tenants/"+tenantA+"/imports",{subject:"ci-api-analyst",method:"POST",body:{...importBody,...patch}});
     assert.equal(changed.status,409);
    }
    const otherCreator=await request("/v1/tenants/"+tenantA+"/imports",{subject:"ci-api-owner",method:"POST",body:importBody});
    assert.equal(otherCreator.status,409);
    assert.equal(JSON.stringify(await otherCreator.json()).includes(createdBody.batch.id),false);

    // Payroll validation: candidate and held decisions are persisted without financial acceptance.
    const testPayroll=[
      {source_ref:"CI-PAY-1",cost_component:"gross_wages",amount:"1250.50",currency:"AUD",period_start:"2026-02-01",period_end:"2026-02-14"},
      {source_ref:"CI-PAY-2",cost_component:"gross_wages",amount:"1e3",currency:"AUD",period_start:"2026-02-01",period_end:"2026-02-14"},
      {source_ref:"CI-PAY-3",cost_component:"gross_wages",amount:"50.00",currency:"AUD",period_start:"2026-02-15",period_end:"2026-03-01"}
    ];
    const payrollId=createdBody.batch.id;
    const unauthorisedUpload=await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/rows",{subject:"ci-api-owner",method:"POST",body:{rows:testPayroll}});
    assert.equal(unauthorisedUpload.status,403,"even an owner must not impersonate the source importer");
    for(const fields of [{employee_name:"SYNTHETIC-PRIVATE-NAME"},{bank_account:"SYNTHETIC-PRIVATE-BANK"},{source_ref:{private:"SYNTHETIC-NESTED"}},{source_ref:"x".repeat(121)}]){
     const invalid=await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/rows",{subject:"ci-api-analyst",method:"POST",body:{rows:[{...testPayroll[0],...fields}]}});
     assert.equal(invalid.status,422);
     assert.equal(invalid.headers.get("cache-control"),"no-store");
     assert.equal(JSON.stringify(await invalid.json()).includes("SYNTHETIC-PRIVATE"),false);
    }
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM raw_import_rows WHERE batch_id=$1",[payrollId])).rows[0].n,0);
    const malformedImport=await fetch(base+"/v1/tenants/"+tenantA+"/imports/"+payrollId+"/rows",{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+await token("ci-api-analyst")},body:"{"});
    assert.equal(malformedImport.status,400);assert.equal(malformedImport.headers.get("cache-control"),"no-store");
    const upload=await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/rows",{subject:"ci-api-analyst",method:"POST",body:{rows:testPayroll}});
    assert.equal(upload.status,201);
    assert.equal((await upload.json()).inserted,3);
    const replay=await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/rows",{subject:"ci-api-analyst",method:"POST",body:{rows:testPayroll}});
    assert.equal(replay.status,201);assert.equal((await replay.json()).duplicates,3);
    const altered=await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/rows",{subject:"ci-api-analyst",method:"POST",body:{rows:[{...testPayroll[0],amount:"999.00"},...testPayroll.slice(1)]}});
    assert.equal(altered.status,409);
    const validatePay=await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/validate",{subject:"ci-api-analyst",method:"POST",body:{}});
    assert.equal(validatePay.status,200);
    const outcome=await validatePay.json();
    assert.deepEqual([outcome.sourceType,outcome.validCandidateRows,outcome.heldRows,outcome.automaticallyAccepted],["payroll",1,2,0]);
    const decisions=await admin.query("SELECT md.decision,md.target_type,md.reason FROM mapping_decisions md JOIN raw_import_rows r ON r.id=md.raw_row_id WHERE r.batch_id=$1 ORDER BY r.row_number",[payrollId]);
    assert.deepEqual(decisions.rows.map(x=>x.decision),["candidate","held","held"]);
    assert.ok(decisions.rows.every(x=>x.target_type==="payroll_row"));
    assert.match(decisions.rows[1].reason,/Amount/);
    assert.match(decisions.rows[2].reason,/outside import batch period/);
    assert.equal((await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/validate",{subject:"ci-api-analyst",method:"POST",body:{}})).status,200);
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM mapping_decisions md JOIN raw_import_rows r ON r.id=md.raw_row_id WHERE r.batch_id=$1",[payrollId])).rows[0].n,3,"revalidation is idempotent");
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM payroll_pools WHERE batch_id=$1",[payrollId])).rows[0].n,0,"structural validation must not create payroll pools");
    assert.equal((await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/validate",{subject:"ci-api-reader",method:"POST",body:{}})).status,403);

    // Reviewer sees validation decisions, never the underlying source payload.
    const payrollReview=await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/review?offset=0&limit=2",{subject:"ci-api-analyst"});
    assert.equal(payrollReview.status,200);
    const queue=await payrollReview.json();
    assert.equal(queue.sourceType,"payroll");
    assert.equal(queue.status,"review");
    assert.deepEqual(queue.summary,{total:3,candidate:1,held:2,accepted:0,rejected:0,unvalidated:0});
    assert.deepEqual(queue.items.map(x=>x.rowNumber),[1,2]);
    assert.deepEqual(queue.items.map(x=>x.decision),["candidate","held"]);
    assert.equal(queue.items[0].reason,null);
    assert.match(queue.items[1].reason,/Amount/);
    const serializedQueue=JSON.stringify(queue);
    for(const sensitive of ["1250.50","CI-PAY-1","gross_wages"])assert.equal(serializedQueue.includes(sensitive),false,"review must not disclose source data");
    const secondPage=await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/review?offset=2&limit=2",{subject:"ci-api-analyst"});
    assert.equal((await secondPage.json()).items[0].rowNumber,3);
    assert.equal((await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/review?limit=101",{subject:"ci-api-analyst"})).status,400);
    assert.equal((await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/review?offset=-1",{subject:"ci-api-analyst"})).status,400);
    assert.equal((await request("/v1/tenants/"+tenantB+"/imports/"+payrollId+"/review",{subject:"ci-api-tenant-b-only"})).status,404,"foreign payroll batch must be hidden");
    assert.equal((await request("/v1/tenants/"+tenantA+"/imports/"+payrollId+"/review",{subject:"ci-api-reader"})).status,403,"read-only members lack review permission");


    const readerWrite=await request(`/v1/tenants/${tenantA}/imports`,{
      subject:"ci-api-reader",method:"POST",
      body:{...importBody,sha256:"c".repeat(64)}
    });
    assert.equal(readerWrite.status,403,"read_only members must not create imports");

    const matchId="99999999-9999-4999-8999-999999999999";
    const analystDecision=await request(`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{subject:"ci-api-analyst",method:"POST",body:{decision:"confirmed",reason:"CI role test"}});
    assert.equal(analystDecision.status,403,"analysts must not finalise match-review decisions");
    const readerDecision=await request(`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{subject:"ci-api-reader",method:"POST",body:{decision:"confirmed",reason:"CI role test"}});
    assert.equal(readerDecision.status,403,"read-only members must not finalise match-review decisions");
    const staleStepUp=await fetch(base+`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+await customToken("ci-api-reviewer",{authTime:Math.floor(Date.now()/1000)-600,acr:"urn:profitpilot:step-up"})},body:JSON.stringify({decision:"confirmed",reason:"CI stale step-up test"})});
    assert.equal(staleStepUp.status,403,"sensitive decisions must reject stale step-up authentication");
    const forgedAssuranceWithoutMfa=await fetch(base+`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+await customToken("ci-api-reviewer",{authTime:Math.floor(Date.now()/1000),acr:"urn:profitpilot:step-up",amr:["pwd"]})},body:JSON.stringify({decision:"confirmed",reason:"CI missing MFA method evidence"})});
    assert.equal(forgedAssuranceWithoutMfa.status,403,"matching assurance without explicit MFA method evidence must not authorise privileged decisions");
    const futureStepUp=await fetch(base+`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+await customToken("ci-api-reviewer",{authTime:Math.floor(Date.now()/1000)+2,acr:"urn:profitpilot:step-up",amr:["mfa"]})},body:JSON.stringify({decision:"confirmed",reason:"CI future authentication timestamp"})});
    assert.equal(futureStepUp.status,403,"future authentication timestamps must never authorise privileged decisions, even with MFA evidence");
    const missingStepUp=await fetch(base+`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{method:"POST",headers:{"content-type":"application/json",authorization:"Bearer "+await customToken("ci-api-reviewer")},body:JSON.stringify({decision:"confirmed",reason:"CI missing step-up test"})});
    assert.equal(missingStepUp.status,403,"sensitive decisions must reject tokens without step-up claims");
    const reviewerDecision=await request(`/v1/tenants/${tenantA}/matches/${matchId}/decision`,{subject:"ci-api-reviewer",method:"POST",body:{}});
    assert.equal(reviewerDecision.status,400,"reviewers must pass role authorisation before decision payload validation");

    const reviewerImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-reviewer",method:"POST",body:{...importBody,sha256:"e".repeat(64)}});
    assert.equal(reviewerImport.status,403,"reviewers must not create source imports");

    {
     const csv="source_ref,cost_component,amount,currency,period_start,period_end\r\nSYNTHETIC-CSV,gross_wages,10.00,AUD,2026-02-01,2026-02-28\r\n";
     const {createHash}=await import("node:crypto");
     const sha256=createHash("sha256").update(csv).digest("hex");
     const createdCsv=await request("/v1/tenants/"+tenantA+"/imports",{subject:"ci-api-analyst",method:"POST",body:{...importBody,sourceType:"payroll",fileName:"synthetic.csv",sha256}});
     assert.equal(createdCsv.status,201);
     const csvBatch=(await createdCsv.json()).batch.id;
     const endpoint="/v1/tenants/"+tenantA+"/imports/"+csvBatch+"/rows/csv";
     const uploadCsv=async(subject,body,contentType="text/csv")=>fetch(base+endpoint,{method:"POST",headers:{authorization:"Bearer "+await token(subject),"content-type":contentType},body});
     assert.equal((await uploadCsv("ci-api-analyst",csv,"application/octet-stream")).status,415);
     assert.equal((await uploadCsv("ci-api-owner",csv)).status,403);
     assert.equal((await uploadCsv("ci-api-analyst",csv.replace("10.00","11.00"))).status,409);
     assert.equal((await admin.query("SELECT count(*)::int AS n FROM raw_import_rows WHERE batch_id=$1",[csvBatch])).rows[0].n,0);
     const stagedCsv=await uploadCsv("ci-api-analyst",csv);
     assert.equal(stagedCsv.status,201,await stagedCsv.clone().text());
     assert.equal((await stagedCsv.json()).checksumVerified,true);
     assert.equal((await uploadCsv("ci-api-analyst",csv)).status,409);
     const stored=(await admin.query("SELECT payload FROM raw_import_rows WHERE batch_id=$1",[csvBatch])).rows[0].payload;
     assert.equal(stored.amount,"10.00");assert.equal(stored.source_ref,"SYNTHETIC-CSV");
     const receipt=await admin.query("SELECT metadata FROM audit_events WHERE object_id=$1 AND action='import_csv_staged'",[csvBatch]);
     assert.equal(receipt.rowCount,1);assert.equal(receipt.rows[0].metadata.sha256,sha256);
    }
    const permissionView=await request(`/v1/tenants/${tenantA}/security/permissions`,{subject:"ci-api-owner"});
    assert.equal(permissionView.status,200,"tenant owners must be able to inspect the permission catalogue and overrides");
    assert.ok((await permissionView.json()).catalogue.some(x=>x.permission_key==="security.audit.read"));
    {
     const acl=(await admin.query("SELECT has_function_privilege('profitpilot_app','private.set_member_permission_override(uuid,uuid,uuid,text,text,text)','EXECUTE') AS legacy_set,has_function_privilege('profitpilot_app','private.remove_member_permission_override(uuid,uuid,uuid,text)','EXECUTE') AS legacy_remove,has_function_privilege('profitpilot_app','private.apply_reviewed_permission_override(uuid,uuid,text,bigint,text)','EXECUTE') AS reviewed")).rows[0];
     assert.deepEqual(acl,{legacy_set:false,legacy_remove:false,reviewed:true});
     const target=userD;
     const now=Math.floor(Date.now()/1000);
     const evidence=JSON.stringify({effect:"deny",permissionKey:"imports.create",reason:"Synthetic proof negative test"});
     await assert.rejects(()=>withTenant(tenantA,"ci-api-owner",c=>c.query("SELECT private.apply_reviewed_permission_override($1,$2,$3,$4,$5)",[tenantA,target,evidence,now,"0".repeat(64)])),/step-up proof/i);
     assert.equal((await admin.query("SELECT count(*)::int AS n FROM tenant_membership_permission_overrides WHERE tenant_id=$1 AND user_id=$2 AND permission_key='imports.create'",[tenantA,target])).rows[0].n,0);
    }
    const ownerGrant=await request(`/v1/tenants/${tenantA}/security/permissions/overrides`,{subject:"ci-api-owner",method:"POST",body:{userId:userD,permissionKey:"imports.create",effect:"grant",reason:"Temporary delegated import authority"}});
    assert.equal(ownerGrant.status,201,"an owner may create a step-up-protected member permission override");
    for(const actor of ["ci-api-owner","ci-api-reviewer"]){
     await assert.rejects(()=>withTenant(tenantA,actor,c=>c.query("SELECT reason,granted_by FROM public.tenant_membership_permission_overrides")),/permission denied/i);
     await assert.rejects(()=>withTenant(tenantA,actor,c=>c.query("SELECT private.read_permission_overrides($1,$2,$3)",[tenantA,Math.floor(Date.now()/1000),"0".repeat(64)])),/step-up proof/i);
    }
    const selfPermission=await withTenant(tenantA,"ci-api-reviewer",c=>c.query("SELECT private.has_scoped_permission($1,'imports.create') AS own,private.has_scoped_permission($2,'imports.create') AS foreign",[tenantA,tenantB]));
    assert.equal(selfPermission.rows[0].own,true);
    assert.equal(selfPermission.rows[0].foreign,false);
    const protectedPermissionView=await request(`/v1/tenants/${tenantA}/security/permissions`,{subject:"ci-api-owner"});
    assert.equal(protectedPermissionView.status,200);
    const protectedPermissionBody=await protectedPermissionView.json();
    assert.equal(protectedPermissionBody.overridesTruncated,false);
    assert.ok(protectedPermissionBody.overrides.some(x=>x.user_id===userD&&x.reason==="Temporary delegated import authority"));
    const deniedPermissionView=await request(`/v1/tenants/${tenantA}/security/permissions`,{subject:"ci-api-reviewer"});
    assert.equal(deniedPermissionView.status,403);
    const grantedImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-reviewer",method:"POST",body:{...importBody,sha256:"1".repeat(64)}});
    assert.equal(grantedImport.status,201,"a member grant must take effect on subsequent API requests");
    const ownerDeny=await request(`/v1/tenants/${tenantA}/security/permissions/overrides`,{subject:"ci-api-owner",method:"POST",body:{userId:userD,permissionKey:"imports.create",effect:"deny",reason:"Remove temporary import authority"}});
    assert.equal(ownerDeny.status,201,"an owner may replace a grant with an explicit denial");
    const deniedImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-reviewer",method:"POST",body:{...importBody,sha256:"2".repeat(64)}});
    assert.equal(deniedImport.status,403,"an explicit member denial must override role defaults and prior grants");
    const removedOverride=await fetch(base+`/v1/tenants/${tenantA}/security/permissions/overrides/${userD}/imports.create`,{method:"DELETE",headers:{"content-type":"application/json",authorization:"Bearer "+await token("ci-api-owner")},body:JSON.stringify({reason:"Return to default role permissions"})});
    assert.equal(removedOverride.status,200,"an owner may remove a member override with a recorded reason");
    const permissionAudit=await admin.query("SELECT action,metadata FROM audit_events WHERE tenant_id=$1 AND object_id=$2 AND object_type='tenant_membership_permission_override' ORDER BY chain_position",[tenantA,userD]);
    assert.deepEqual(permissionAudit.rows.map(x=>x.action),["member_permission_override_set","member_permission_override_set","member_permission_override_removed"]);
    assert.deepEqual(permissionAudit.rows.map(x=>x.metadata.effect??"removed"),["grant","deny","removed"]);
    const auditView=await request(`/v1/tenants/${tenantA}/security/audit?limit=20`,{subject:"ci-api-owner"});
    assert.equal(auditView.status,200,"tenant owners must be able to inspect security audit events");
    const auditBody=await auditView.json();
    assert.equal(auditBody.integrity.is_valid,true,"the tenant audit hash chain must verify");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-owner",c=>c.query("INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason) VALUES($1,$2,'privacy_account_export_released','privacy_request',$3,'Forged event')",[tenantA,userA,tenantA])),/permission denied/i);
    await assert.rejects(()=>withTenant(tenantA,"ci-api-owner",c=>c.query("SELECT private.append_verified_audit($1,$2)",[JSON.stringify({tenantId:tenantA,actorId:userA,action:"invoice_batch_prepared"}),"0".repeat(64)])),/audit attestation/i);
    for(const actor of ["ci-api-analyst","ci-api-owner"]){
     await assert.rejects(()=>withTenant(tenantA,actor,c=>c.query("SELECT reason,metadata FROM audit_events")),/permission denied/i);
     await assert.rejects(()=>withTenant(tenantA,actor,c=>c.query("SELECT * FROM private.verify_audit_chain($1)",[tenantB])),/permission denied/i);
     await assert.rejects(()=>withTenant(tenantA,actor,c=>c.query("SELECT private.read_audit_summary($1,$2,$3,$4)",[tenantA,20,Math.floor(Date.now()/1000),"0".repeat(64)])),/step-up proof/i);
    }
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("SELECT * FROM private.read_invoice_manifest_events($1,$2)",[tenantA,tenantA])),/Financial review permissions/i);
    await assert.rejects(()=>withTenant(tenantA,"ci-api-owner",c=>c.query("SELECT * FROM private.read_invoice_manifest_events($1,$2)",[tenantB,tenantB])),/Financial review permissions/i);
    const privacySubmit=await request(`/v1/tenants/${tenantA}/privacy/requests`,{subject:"ci-api-analyst",method:"POST",body:{requestType:"access",details:"Please provide a copy of personal information held about me."}});
    assert.equal(privacySubmit.status,201,"tenant members must be able to submit privacy requests");
    const privacyItem=await privacySubmit.json();
    const secondPrivacySubmit=await request(`/v1/tenants/${tenantA}/privacy/requests`,{subject:"ci-api-reader",method:"POST",body:{requestType:"access",details:"Please provide the personal information held about me."}});
    assert.equal(secondPrivacySubmit.status,201,"a second member may submit their own privacy request");
    const secondPrivacyItem=await secondPrivacySubmit.json();
    const privacyMine=await request(`/v1/tenants/${tenantA}/privacy/requests`,{subject:"ci-api-analyst"});
    assert.equal(privacyMine.status,200);
    assert.deepEqual((await privacyMine.json()).items.map(item=>item.id),[privacyItem.id],"members must see only their own privacy requests");
    const analystDatabasePrivacyRows=await withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT id FROM privacy_requests ORDER BY id"));
    assert.deepEqual(analystDatabasePrivacyRows.rows.map(row=>row.id),[privacyItem.id],"PostgreSQL RLS must hide another member's privacy request even from direct runtime SQL");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("INSERT INTO privacy_requests(tenant_id,subject_user_id,submitted_by,request_type,details) VALUES($1,$2,$2,'access','Attempt to submit for another member')",[tenantA,userB])),/row-level security/i,"members must not submit privacy requests on behalf of another member");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("UPDATE privacy_requests SET status='withdrawn' WHERE id=$1",[secondPrivacyItem.id])),/permission denied/i,"runtime role cannot directly update privacy requests");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-owner",client=>client.query("UPDATE privacy_requests SET status='fulfilled', resolved_at=now() WHERE id=$1",[privacyItem.id])),/permission denied/i,"even a manager cannot bypass the decision function");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("INSERT INTO privacy_requests(tenant_id,subject_user_id,submitted_by,request_type,details,status) VALUES($1,$2,$2,'access','Forged state','under_review')",[tenantA,userA])),/permission denied/i,"runtime role cannot insert a fabricated request status");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",client=>client.query("SELECT private.confirm_privacy_account($1,$2,$3,$4)",[tenantA,privacyItem.id,Math.floor(Date.now()/1000),"0".repeat(64)])),/step-up proof/i,"database denies forged account confirmation");
    const secondWithdraw=await request(`/v1/tenants/${tenantA}/privacy/requests/${secondPrivacyItem.id}/withdraw`,{subject:"ci-api-reader",method:"POST",body:{reason:"Request withdrawn by its submitter"}});
    assert.equal(secondWithdraw.status,200,"a member may withdraw their own pending request through the constrained database function");
    assert.equal((await secondWithdraw.json()).status,"withdrawn");
    const privacyManage=await request(`/v1/tenants/${tenantA}/privacy/requests/manage`,{subject:"ci-api-owner"});
    assert.equal(privacyManage.status,200,"owners must be able to review tenant privacy requests");
    {
    const queue=await privacyManage.json();
    assert.equal(queue.items.length,2,"privacy managers may review metadata across their tenant");
    assert.equal(queue.scope,"metadata_only");
    assert.ok(queue.items.every(x=>!Object.hasOwn(x,"details")&&!Object.hasOwn(x,"legal_hold_reason")&&!Object.hasOwn(x,"resolution_summary")));
    const ordinaryOwnerToken=await customToken("ci-api-owner");
    const ownerNoMfa=async path=>fetch(base+path,{headers:{authorization:"Bearer "+ordinaryOwnerToken}});
    for(const route of ["/privacy/requests/manage","/security/audit","/security/permissions"])assert.equal((await ownerNoMfa("/v1/tenants/"+tenantA+route)).status,403);
    const managerRows=await withTenant(tenantA,"ci-api-owner",c=>c.query("SELECT id,details FROM privacy_requests"));
    assert.equal(managerRows.rowCount,0,"direct manager SQL cannot read other subjects' narratives");
    const detailPath="/v1/tenants/"+tenantA+"/privacy/requests/"+privacyItem.id+"/read-details";
    const accessPurpose={reason:"Investigate request for information"};
    assert.equal((await request(detailPath,{subject:"ci-api-analyst",method:"POST",body:accessPurpose})).status,403);
    assert.equal((await fetch(base+detailPath,{method:"POST",headers:{authorization:"Bearer "+ordinaryOwnerToken,"content-type":"application/json"},body:JSON.stringify(accessPurpose)})).status,403);
    assert.equal((await request(detailPath,{subject:"ci-api-owner",method:"POST",body:{reason:""}})).status,400);
    assert.equal((await request("/v1/tenants/"+tenantB+"/privacy/requests/"+privacyItem.id+"/read-details",{subject:"ci-api-tenant-b-only",method:"POST",body:accessPurpose})).status,403);
    await assert.rejects(()=>withTenant(tenantA,"ci-api-owner",c=>c.query("SELECT private.read_privacy_details($1,$2,$3,$4,$5)",[tenantA,privacyItem.id,accessPurpose.reason,Math.floor(Date.now()/1000),"0".repeat(64)])),/step-up proof/i);
    const inspected=await request(detailPath,{subject:"ci-api-owner",method:"POST",body:accessPurpose});
    assert.equal(inspected.status,200);
    assert.match((await inspected.json()).details,/copy of personal information/);
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM audit_events WHERE object_id=$1 AND action='privacy_request_details_read'",[privacyItem.id])).rows[0].n,1);
    const auditMetadata=await request("/v1/tenants/"+tenantA+"/security/audit",{subject:"ci-api-owner"});
    const meta=await auditMetadata.json();
    assert.equal(meta.scope,"audit_metadata_only");
    assert.ok(meta.items.every(x=>!Object.hasOwn(x,"reason")&&!Object.hasOwn(x,"metadata")));
    }
    const verifyPrivacy=await request(`/v1/tenants/${tenantA}/privacy/requests/${privacyItem.id}/decision`,{subject:"ci-api-owner",method:"POST",body:{action:"verify_identity",reason:"Identity evidence reviewed"}});
    assert.equal(verifyPrivacy.status,200);
    const beginPrivacy=await request(`/v1/tenants/${tenantA}/privacy/requests/${privacyItem.id}/decision`,{subject:"ci-api-owner",method:"POST",body:{action:"begin_review",reason:"Identity evidence not independently verified"}});
    assert.equal(beginPrivacy.status,409,"privacy review must remain blocked until real identity verification is implemented");
    const confirmPath="/v1/tenants/"+tenantA+"/privacy/requests/"+privacyItem.id+"/confirm-account";
    const wrongAccount=await request(confirmPath,{subject:"ci-api-owner",method:"POST"});
    assert.equal(wrongAccount.status,404,"manager cannot confirm another member's account");
    const noMfaConfirm=await fetch(base+confirmPath,{method:"POST",headers:{authorization:"Bearer "+await customToken("ci-api-analyst",{authTime:Math.floor(Date.now()/1000),acr:"urn:profitpilot:step-up",amr:["pwd"]})}});
    assert.equal(noMfaConfirm.status,403,"account confirmation requires explicit MFA evidence");
    const confirmationToken=await token("ci-api-analyst");
    const confirmed=await fetch(base+confirmPath,{method:"POST",headers:{authorization:"Bearer "+confirmationToken}});
    assert.equal(confirmed.status,200,"only the requester can confirm account control with MFA");
    assert.ok((await confirmed.json()).account_confirmed_at);
    const reviewed=await request("/v1/tenants/"+tenantA+"/privacy/requests/"+privacyItem.id+"/decision",{subject:"ci-api-owner",method:"POST",body:{action:"begin_review",reason:"Requester MFA confirmation reviewed"}});
    assert.equal(reviewed.status,200);
    assert.equal((await reviewed.json()).status,"under_review");
    const exportBase="/v1/tenants/"+tenantA+"/privacy/requests/"+privacyItem.id;
    assert.equal((await request(exportBase+"/export",{subject:"ci-api-analyst",method:"POST"})).status,409,"review is not an export approval");
    assert.equal((await request(exportBase+"/approve-export",{subject:"ci-api-analyst",method:"POST"})).status,403,"ordinary requester cannot approve export");
    assert.equal((await request(exportBase+"/approve-export",{subject:"ci-api-owner",method:"POST"})).status,200,"independent manager approves restricted export");
    assert.equal((await request(exportBase+"/approve-export",{subject:"ci-api-owner",method:"POST"})).status,409,"active approval cannot be extended");
    assert.equal((await request(exportBase+"/export",{subject:"ci-api-owner",method:"POST"})).status,404,"owner cannot extract another member's account");
    assert.equal((await request(exportBase+"/export",{subject:"ci-api-reader",method:"POST"})).status,404,"other member cannot extract account");
    assert.equal((await request(exportBase+"/export",{subject:"ci-api-tenant-b-only",method:"POST"})).status,403,"cross-tenant requester denied");
    assert.equal((await request("/v1/tenants/"+tenantB+"/privacy/requests/"+privacyItem.id+"/export",{subject:"ci-api-tenant-b-only",method:"POST"})).status,404,"foreign request ID does not leak");
    assert.equal((await fetch(base+exportBase+"/export",{method:"POST",headers:{authorization:"Bearer "+await customToken("ci-api-analyst",{authTime:Math.floor(Date.now()/1000),acr:"urn:profitpilot:step-up",amr:["pwd"]})}})).status,403,"MFA required for export release");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("SELECT * FROM private.privacy_export_approvals")),/permission denied/i);
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("SELECT private.release_account_export($1,$2,$3,$4)",[tenantA,privacyItem.id,Math.floor(Date.now()/1000),"0".repeat(64)])),/step-up proof/i);
    // Expire the grant via CI-only administration, then confirm it cannot be used.
    await admin.query("UPDATE private.privacy_export_approvals SET approved_at=clock_timestamp()-interval '16 minutes',expires_at=clock_timestamp()-interval '1 minute' WHERE request_id=$1",[privacyItem.id]);
    assert.equal((await request(exportBase+"/export",{subject:"ci-api-analyst",method:"POST"})).status,409,"expired approval denied");
    assert.equal((await request(exportBase+"/approve-export",{subject:"ci-api-owner",method:"POST"})).status,200,"expired grant can be replaced by independent approval");
    await admin.query("UPDATE private.privacy_export_approvals SET scope='account-v1' WHERE request_id=$1",[privacyItem.id]);
    assert.equal((await request(exportBase+"/export",{subject:"ci-api-analyst",method:"POST"})).status,409,"old approval cannot authorize expanded scope");
    assert.equal((await request(exportBase+"/approve-export",{subject:"ci-api-owner",method:"POST"})).status,200,"expanded scope needs independent reapproval");
    await new Promise(resolve=>setTimeout(resolve,1100));
    const releases=await Promise.all([request(exportBase+"/export",{subject:"ci-api-analyst",method:"POST"}),request(exportBase+"/export",{subject:"ci-api-analyst",method:"POST"})]);
    assert.deepEqual(releases.map(x=>x.status).sort(),[200,409],"concurrent release consumes approval exactly once");
    const downloaded=releases.find(x=>x.status===200);
    assert.match(downloaded.headers.get("cache-control"),/no-store/);
    assert.match(downloaded.headers.get("content-disposition"),/attachment/);
    const exported=await downloaded.json();
    assert.equal(exported.completePersonalDataExport,false);
    assert.equal(exported.scope,"account-v2");
    assert.equal(exported.schemaVersion,2);
    const ownImports=await admin.query("SELECT created_at FROM import_batches WHERE tenant_id=$1 AND created_by=$2 ORDER BY created_at,id",[tenantA,userA]);
    assert.equal(ownImports.rowCount,2,"fixture has exactly two own import records");
    assert.deepEqual(exported.attributedActivity.filter(x=>x.kind==="import_created").map(x=>new Date(x.at).toISOString()).sort(),ownImports.rows.map(x=>x.created_at.toISOString()).sort(),"export includes exactly the requester's import attribution");
    assert.ok(exported.attributedActivity.every(x=>Object.keys(x).sort().join(",")==="at,kind"),"no business record fields in activity projection");
    assert.deepEqual(Object.keys(exported.account).sort(),["createdAt","email","status"]);
    assert.equal(exported.account.email,"analyst@example.invalid");
    assert.equal(exported.membership.tenantId,tenantA);
    assert.deepEqual(exported.privacyRequestMetadata.map(x=>x.id),[privacyItem.id]);
    assert.equal(exported.privacyRequestMetadata[0].status,"under_review");
    assert.equal(Object.hasOwn(exported.privacyRequestMetadata[0],"details"),false);
    const serialized=JSON.stringify(exported);
    for(const other of ["reader@example.invalid","owner@example.invalid","tenant-b@example.invalid",secondPrivacyItem.id,tenantB,"ci-api-analyst","Please provide a copy"])assert.equal(serialized.includes(other),false,"exclude other members, identity subject and free text");
    const auditReleaseCount=await admin.query("SELECT count(*)::int AS n FROM audit_events WHERE object_id=$1 AND action='privacy_account_export_released'",[privacyItem.id]);
    assert.equal(auditReleaseCount.rows[0].n,1);
    assert.equal((await request(exportBase+"/approve-export",{subject:"ci-api-owner",method:"POST"})).status,200,"independent reapproval supports delivery retry");
    const holdPrivacy=await request("/v1/tenants/"+tenantA+"/privacy/requests/"+privacyItem.id+"/decision",{subject:"ci-api-owner",method:"POST",body:{action:"place_legal_hold",reason:"Preserve records for an active dispute"}});
    assert.equal(holdPrivacy.status,200);
    assert.equal((await request(exportBase+"/export",{subject:"ci-api-analyst",method:"POST"})).status,409,"legal hold blocks release");
    const holdRelease=await request("/v1/tenants/"+tenantA+"/privacy/requests/"+privacyItem.id+"/decision",{subject:"ci-api-owner",method:"POST",body:{action:"release_legal_hold",reason:"Dispute concluded; repeat verification"}});
    assert.equal(holdRelease.status,200);
    assert.equal((await holdRelease.json()).status,"identity_verification","hold release must return to verification");
    assert.equal((await request(exportBase+"/export",{subject:"ci-api-analyst",method:"POST"})).status,409,"prior approval cannot bypass hold release");
    const replayAfterHold=await fetch(base+confirmPath,{method:"POST",headers:{authorization:"Bearer "+confirmationToken}});
    assert.equal(replayAfterHold.status,409,"the earlier authentication event cannot be replayed after hold release");
    const reviewAfterHold=await request("/v1/tenants/"+tenantA+"/privacy/requests/"+privacyItem.id+"/decision",{subject:"ci-api-owner",method:"POST",body:{action:"begin_review",reason:"Attempt without fresh confirmation"}});
    assert.equal(reviewAfterHold.status,409,"hold release invalidates previous confirmation");
    const fulfilPrivacy=await request("/v1/tenants/"+tenantA+"/privacy/requests/"+privacyItem.id+"/decision",{subject:"ci-api-owner",method:"POST",body:{action:"fulfil",reason:"Attempt to close without execution",resolutionSummary:"Not proof of fulfilment"}});
    assert.equal(fulfilPrivacy.status,409,"unsupported fulfilment must stay blocked");
    const pending=await request("/v1/tenants/"+tenantA+"/privacy/requests/manage",{subject:"ci-api-owner"});
    assert.equal(pending.status,200);
    const pendingItem=(await pending.json()).items.find(item=>item.id===privacyItem.id);
    assert.equal(pendingItem.status,"identity_verification");
    assert.equal(pendingItem.account_confirmed_at,null);
    // Runtime role must not bypass workflow by deleting requests or changing role grants.
    await assert.rejects(()=>withTenant(tenantA,"ci-api-owner",c=>c.query("DELETE FROM privacy_requests WHERE id=$1",[secondPrivacyItem.id])),/permission denied/i);
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("UPDATE tenant_memberships SET role='owner' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA])),/permission denied/i);
    await assert.rejects(()=>withTenant(tenantA,"ci-api-analyst",c=>c.query("INSERT INTO role_permissions(role,permission_key) VALUES('analyst','privacy.requests.manage')")),/permission denied/i);
    const deletion=await request("/v1/tenants/"+tenantA+"/privacy/requests",{subject:"ci-api-reader",method:"POST",body:{requestType:"deletion",details:"Remove my closed request narrative"}});
    assert.equal(deletion.status,201);
    const deletionId=(await deletion.json()).id;
    const deletionBase="/v1/tenants/"+tenantA+"/privacy/requests/"+deletionId;
    const redactionBody={targetRequestId:secondPrivacyItem.id};
    assert.equal((await request(deletionBase+"/decision",{subject:"ci-api-owner",method:"POST",body:{action:"verify_identity",reason:"Begin deletion verification"}})).status,200);
    assert.equal((await request(deletionBase+"/confirm-account",{subject:"ci-api-reader",method:"POST"})).status,200);
    assert.equal((await request(deletionBase+"/decision",{subject:"ci-api-owner",method:"POST",body:{action:"begin_review",reason:"Confirmed request ownership"}})).status,200);
    // CI-only fixtures. No production policy is seeded by migrations.
    assert.equal((await request(deletionBase+"/approve-redaction",{subject:"ci-api-owner",method:"POST",body:redactionBody})).status,409,"absent retention policy fails closed");
    const policyId="dddddddd-dddd-4ddd-8ddd-dddddddddddd";
    await admin.query("INSERT INTO private.privacy_retention_policies(tenant_id,revision,enabled,minimum_closed_age_days,authority_reference) VALUES($1,$2,true,30,'CI synthetic policy only')",[tenantA,policyId]);
    assert.equal((await request(deletionBase+"/approve-redaction",{subject:"ci-api-owner",method:"POST",body:redactionBody})).status,409,"minimum age protects recent records");
    await admin.query("UPDATE privacy_requests SET updated_at=clock_timestamp()-interval '31 days' WHERE id=$1",[secondPrivacyItem.id]);
    assert.equal((await request(deletionBase+"/approve-redaction",{subject:"ci-api-owner",method:"POST",body:{targetRequestId:privacyItem.id}})).status,404,"cannot approve deletion of another member's request");
    assert.equal((await request(deletionBase+"/approve-redaction",{subject:"ci-api-owner",method:"POST",body:redactionBody})).status,200);
    const {withPrivacyStepUp}=await import("../server/db.js");
    const readerMembership={tenantId:tenantA,userId:userB};
    async function directRedaction(action,member=readerMembership,subject="ci-api-reader",authTime=Math.floor(Date.now()/1000)){
     return withPrivacyStepUp(member,{subject,authTime},deletionId,action+":"+secondPrivacyItem.id,async(c,proof)=>{
      const r=await c.query("SELECT private."+action+"($1,$2,$3,$4,$5) AS result",[tenantA,deletionId,secondPrivacyItem.id,authTime,proof]);
      return r.rows[0].result;
     });
    }
    await assert.rejects(()=>withTenant(tenantA,"ci-api-reader",c=>c.query("SELECT * FROM private.privacy_redaction_approvals")),/permission denied/i);
    await assert.rejects(()=>withTenant(tenantA,"ci-api-reader",c=>c.query("SELECT private.execute_request_redaction($1,$2,$3,$4,$5)",[tenantA,deletionId,secondPrivacyItem.id,Math.floor(Date.now()/1000),"0".repeat(64)])),/step-up proof/i);
    assert.equal((await directRedaction("execute_request_redaction",{tenantId:tenantA,userId:userE},"ci-api-owner")).status,404,"manager cannot execute another person's deletion");
    await new Promise(resolve=>setTimeout(resolve,1100));
    await admin.query("INSERT INTO private.privacy_retention_holds(tenant_id,subject_user_id,authority_reference) VALUES($1,$2,'CI subject-wide legal hold')",[tenantA,userB]);
    assert.equal((await directRedaction("execute_request_redaction")).status,409,"subject hold blocks even previously approved deletion");
    await admin.query("DELETE FROM private.privacy_retention_holds WHERE tenant_id=$1 AND subject_user_id=$2",[tenantA,userB]);
    assert.equal((await directRedaction("execute_request_redaction")).status,409,"released hold cannot resurrect old approval");
    assert.equal((await directRedaction("approve_request_redaction",{tenantId:tenantA,userId:userE},"ci-api-owner")).status,200,"new approval required after hold release");
    await new Promise(resolve=>setTimeout(resolve,1100));
    await admin.query("UPDATE private.privacy_retention_policies SET enabled=false WHERE tenant_id=$1",[tenantA]);
    assert.equal((await directRedaction("execute_request_redaction")).status,409,"policy disabled after approval blocks execution");
    await admin.query("UPDATE private.privacy_retention_policies SET enabled=true WHERE tenant_id=$1",[tenantA]);
    assert.equal((await directRedaction("execute_request_redaction")).status,409,"re-enabled policy cannot resurrect old approval");
    assert.equal((await directRedaction("approve_request_redaction",{tenantId:tenantA,userId:userE},"ci-api-owner")).status,200,"new policy revision requires fresh approval");
    const approvedEpoch=(await admin.query("SELECT floor(extract(epoch FROM approved_at))::bigint AS epoch FROM private.privacy_redaction_approvals WHERE request_id=$1",[deletionId])).rows[0].epoch;
    assert.equal((await directRedaction("execute_request_redaction",readerMembership,"ci-api-reader",Number(approvedEpoch))).status,409,"same-second prior authentication cannot authorize deletion");
    await new Promise(resolve=>setTimeout(resolve,1100));
    const before=await admin.query("SELECT details FROM privacy_requests WHERE id=$1",[secondPrivacyItem.id]);
    assert.match(before.rows[0].details,/personal information/);
    const redacted=await request(deletionBase+"/execute-redaction",{subject:"ci-api-reader",method:"POST",body:redactionBody});
    assert.equal(redacted.status,200,"requester executes narrowly approved deletion after new MFA");
    assert.equal((await redacted.json()).completePersonalDataDeletion,false);
    assert.equal((await directRedaction("execute_request_redaction")).status,409,"redaction approval is single-use");
    const after=await admin.query("SELECT details,details_redacted_at,status FROM privacy_requests WHERE id=$1",[secondPrivacyItem.id]);
    assert.equal(after.rows[0].details,"[Removed under approved retention policy]");
    assert.ok(after.rows[0].details_redacted_at);
    assert.equal(after.rows[0].status,"withdrawn","retain legal record");
    await assert.rejects(()=>admin.query("UPDATE privacy_requests SET details='Restore deleted narrative' WHERE id=$1",[secondPrivacyItem.id]),/Redacted data must not be restored/);
    const restoreState=(await admin.query("SELECT private.privacy_restore_state() AS state")).rows[0].state;
    assert.deepEqual(restoreState.violations,[]);
    const marker=restoreState.markers.find(m=>m.kind==="redaction"&&m.id===secondPrivacyItem.id);
    assert.ok(marker,"actual redaction appears in restore evidence");
    const {signCheckpoint,verifyCheckpoint,checkpointDigest}=await import("../scripts/privacy-restore-checkpoint.js");
    const opts={key:"ef".repeat(32),deploymentId:"ci-redaction",now:Date.now()};
    const checkpoint=signCheckpoint(restoreState,opts);
    const verifyOpts={...opts,expectedDigest:checkpointDigest(checkpoint)};
    assert.equal(verifyCheckpoint(checkpoint,restoreState,verifyOpts).verified,true);
    assert.throws(()=>verifyCheckpoint(checkpoint,{...restoreState,markers:restoreState.markers.filter(m=>m.id!==secondPrivacyItem.id)},verifyOpts),/missing or has changed/);
    assert.equal((await admin.query("SELECT status FROM privacy_requests WHERE id=$1",[deletionId])).rows[0].status,"under_review","partial deletion is not full fulfilment");
    assert.equal((await admin.query("SELECT count(*)::int AS n FROM audit_events WHERE object_id=$1 AND action='privacy_redaction_executed'",[deletionId])).rows[0].n,1);
    const privacyAudit=await request(`/v1/tenants/${tenantA}/security/audit?limit=100`,{subject:"ci-api-owner"});
    assert.equal((await privacyAudit.json()).integrity.is_valid,true,"privacy request events must remain verifiable in the audit chain");
    const privacyOtherTenant=await request(`/v1/tenants/${tenantB}/privacy/requests/manage`,{subject:"ci-api-tenant-b-only"});
    assert.equal(privacyOtherTenant.status,403,"privacy requests must remain tenant-scoped and require manager permission");
    assert.ok(auditBody.integrity.event_count>=3,"permission changes must be recorded in the append-only audit chain");
    await assert.rejects(()=>withTenant(tenantA,"ci-api-owner",client=>client.query("UPDATE audit_events SET reason='tampered' WHERE tenant_id=$1",[tenantA])),/permission denied/i,"the runtime role must not update append-only audit events");
    const memberCannotManage=await request(`/v1/tenants/${tenantA}/security/permissions/overrides`,{subject:"ci-api-reviewer",method:"POST",body:{userId:userA,permissionKey:"imports.create",effect:"grant",reason:"Must be denied"}});
    assert.equal(memberCannotManage.status,403,"non-owners must not manage member permission overrides");
    await admin.query("INSERT INTO tenant_membership_permission_overrides(tenant_id,user_id,permission_key,effect,reason,granted_by) VALUES ($1,$2,'imports.create','grant','Temporary CI override grant',$2)",[tenantA,userD]);
    const overriddenReviewerImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-reviewer",method:"POST",body:{...importBody,sha256:"f".repeat(64)}});
    assert.equal(overriddenReviewerImport.status,201,"an explicit tenant-scoped member grant must override the role default");
    await admin.query("UPDATE tenant_membership_permission_overrides SET effect='deny',reason='Temporary CI override denial' WHERE tenant_id=$1 AND user_id=$2 AND permission_key='imports.create'",[tenantA,userD]);
    const deniedReviewerImport=await request(`/v1/tenants/${tenantA}/imports`,{subject:"ci-api-reviewer",method:"POST",body:{...importBody,sha256:"a".repeat(64)}});
    assert.equal(deniedReviewerImport.status,403,"an explicit tenant-scoped member denial must override a role grant");
    await admin.query("DELETE FROM tenant_membership_permission_overrides WHERE tenant_id=$1 AND user_id=$2 AND permission_key='imports.create'",[tenantA,userD]);
    const reviewerRows=await request(`/v1/tenants/${tenantA}/imports/${matchId}/rows`,{subject:"ci-api-reviewer",method:"POST",body:{rows:[{invoice:"CI"}]}});
    assert.equal(reviewerRows.status,403,"reviewers must not ingest source rows");
    const analystRows=await request(`/v1/tenants/${tenantA}/imports/${matchId}/rows`,{subject:"ci-api-analyst",method:"POST",body:{rows:[{invoice:"CI"}]}});
    assert.equal(analystRows.status,404,"analysts may ingest rows, subject to tenant-scoped batch existence");

    const readerValidation=await request(`/v1/tenants/${tenantA}/imports/${matchId}/validate`,{subject:"ci-api-reader",method:"POST",body:{}});
    assert.equal(readerValidation.status,403,"read-only members must not initiate validation");
    const reviewerValidation=await request(`/v1/tenants/${tenantA}/imports/${matchId}/validate`,{subject:"ci-api-reviewer",method:"POST",body:{}});
    assert.equal(reviewerValidation.status,404,"reviewers may validate only an existing tenant-scoped batch");

    const readerCalculation=await request(`/v1/tenants/${tenantA}/calculations`,{subject:"ci-api-reader",method:"POST",body:{}});
    assert.equal(readerCalculation.status,403,"read-only members must not create calculations");
    const analystCalculation=await request(`/v1/tenants/${tenantA}/calculations`,{subject:"ci-api-analyst",method:"POST",body:{}});
    assert.equal(analystCalculation.status,400,"analysts may initiate calculations subject to valid inputs");

    await admin.query("UPDATE tenant_memberships SET status='revoked' WHERE tenant_id=$1 AND user_id=$2",[tenantA,userA]);
    const revoked=await request(`/v1/tenants/${tenantA}/contracts`,{subject:"ci-api-analyst"});
    assert.equal(revoked.status,403,"revoked memberships must lose access immediately");
  }finally{
    await new Promise(resolve=>api.close(resolve));
    await admin.end();
    await appPool.end();
    await new Promise(resolve=>jwksServer.close(resolve));
  }
});
