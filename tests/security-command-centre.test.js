import test from "node:test";
import assert from "node:assert/strict";
import {rootCertificates} from "node:tls";
import {X509Certificate} from "node:crypto";
import {parseSecurityPage,securityReaderConfig,validateSnapshot,readSecuritySnapshot} from "../scripts/security-command-centre.js";
const incidentId="11111111-1111-4111-8111-111111111111",tenantId="22222222-2222-4222-8222-222222222222";
const report={schemaVersion:1,observedAt:"2026-11-18T00:00:00Z",catalogVerified:true,status:"containment_active",counts:{activeTenantIncidents:1,temporarilyContainedActors:0,identitySecurityEvents24h:0,pendingOrRetryableScans:0,processingScans:0,pendingOrProcessingPromotions:0,failedPromotions:0},activeIncidents:[{incidentId,tenantId,category:"suspected_compromise",activatedAt:"2026-11-18T00:00:00Z"}],nextCursor:null};
test("security command accepts only bounded UUID pages",()=>{
 assert.deepEqual(parseSecurityPage([]),{limit:50,cursor:null});
 assert.deepEqual(parseSecurityPage(["100",incidentId]),{limit:100,cursor:incidentId});
 for(const args of [["0"],["101"],["1.0"],["50 "],["1","bogus"],["1",incidentId,"extra"]])assert.throws(()=>parseSecurityPage(args));
});
test("security report validation rejects unknown fields and inconsistent containment",()=>{
 assert.deepEqual(validateSnapshot(report),report);
 for(const bad of [
 {...report,rawFinancialData:[]},
 {...report,counts:{...report.counts,temporarilyContainedActors:-1}},
 {...report,activeIncidents:[{...report.activeIncidents[0],authorityRef:"not-for-reader"}]},
 {...report,activeIncidents:[{...report.activeIncidents[0],category:"arbitrary"}]},
 {...report,status:"no_active_containment"},
 {...report,nextCursor:incidentId},
 {...report,catalogVerified:false,status:"catalog_drift"}
 ])assert.throws(()=>validateSnapshot(bad));
 const drift={schemaVersion:1,observedAt:report.observedAt,catalogVerified:false,status:"catalog_drift",counts:null,activeIncidents:null,nextCursor:null};
 assert.deepEqual(validateSnapshot(drift),drift);
 assert.throws(()=>validateSnapshot(report,{limit:1,cursor:incidentId}));
});
test("restricted reader requires explicit verified TLS and rejects unsafe connection overrides",()=>{
 const ca=rootCertificates.find(pem=>{const c=new X509Certificate(pem);return c.ca&&Date.parse(c.validFrom)<=Date.now()&&Date.parse(c.validTo)>Date.now();});
 const valid={SECURITY_READER_DATABASE_URL:"postgresql://profitpilot_security_reader:"+"a".repeat(24)+"@db.example.invalid/profitpilot",SECURITY_READER_DATABASE_CA:ca};
 assert.equal(securityReaderConfig(valid).ssl.rejectUnauthorized,true);
 for(const change of [{NODE_TLS_REJECT_UNAUTHORIZED:"0"},{PGOPTIONS:"-c statement_timeout=0"},{SECURITY_READER_DATABASE_CA:"invalid"},{SECURITY_READER_DATABASE_URL:valid.SECURITY_READER_DATABASE_URL+"?sslmode=disable"},{SECURITY_READER_DATABASE_URL:valid.SECURITY_READER_DATABASE_URL.replace("profitpilot_security_reader","profitpilot_app")}])assert.throws(()=>securityReaderConfig({...valid,...change}));
});
test("snapshot reader uses a fixed parameterized query",async()=>{
 const page={limit:50,cursor:null};
 const db={query:async(sql,args)=>{assert.equal(sql,"SELECT private.security_command_snapshot($1,$2) AS report");assert.deepEqual(args,[50,null]);return {rowCount:1,rows:[{report}]};}};
 assert.deepEqual(await readSecuritySnapshot(db,page),report);
});
