import test from "node:test";
import assert from "node:assert/strict";
import {profileMigration} from "../src/switchproof-migration.js";

const manifest={sourceSystem:"legacy-accounting",sourceSha256:"a".repeat(64),permissionReference:"owner-export-approval",sourceKeyField:"row_id",mappingVersion:"map-v1",expectedRowCount:2,controlTotal:"300.00",currency:"AUD",taxBasis:"gst_exclusive",periodStart:"2026-11-01",periodEnd:"2026-11-30"};
const mappings=[{target:"sourceId",source:"row_id"},{target:"amount",source:"amount_text"},{target:"date",source:"service_date"},{target:"currency",source:"currency_code"}];
const rows=[{row_id:"row-1",amount_text:"100.00",service_date:"2026-11-01",currency_code:"AUD"},{row_id:"row-2",amount_text:"200.00",service_date:"2026-11-02",currency_code:"AUD"}];

test("a reconciled source profile is ready for human review but never migrates automatically",()=>{
  const result=profileMigration({manifest,mappings,requiredTargets:["sourceId","amount","date","currency"],rows});
  assert.equal(result.status,"ready_for_human_review");
  assert.equal(result.controlTotalMatches,true);
  assert.equal(result.sourceControlTotal,"300.00");
  assert.equal(result.parsedTotal,"300.00");
  assert.equal(result.migrationAccepted,false);
  assert.equal(result.automatedMerge,false);
  assert.equal(result.sourceDataCopied,false);
});

test("duplicate source keys, row count and source totals block migration",()=>{
  const result=profileMigration({manifest,mappings,requiredTargets:["sourceId","amount","date","currency"],rows:[rows[0],{...rows[1],row_id:"row-1",amount_text:"201.00"}]});
  assert.equal(result.status,"blocked");
  assert.equal(result.duplicateSourceKeys,1);
  assert.equal(result.controlTotalMatches,false);
  assert.ok(result.exceptions.some(x=>x.code==="source_control_total_mismatch"));
});

test("missing mappings and malformed manifest fail closed",()=>{
  assert.throws(()=>profileMigration({manifest,mappings:[{target:"amount",source:"amount_text"}],requiredTargets:["date"],rows}),/required target/);
  assert.throws(()=>profileMigration({manifest:{...manifest,sourceSha256:"bad"},mappings,requiredTargets:["sourceId"],rows}),/Source manifest/);
});

test("missing values, invalid dates and currency mismatches are reported without copying row content",()=>{
  const result=profileMigration({manifest,mappings,requiredTargets:["sourceId","amount","date","currency"],rows:[{row_id:"row-1",amount_text:"1e3",service_date:"2026-02-31",currency_code:"NZD"},{row_id:"row-2",amount_text:"2.00",service_date:"2026-11-02",currency_code:"AUD"}]});
  assert.equal(result.status,"blocked");
  assert.ok(result.exceptions.some(x=>x.code==="invalid_amount"));
  assert.ok(result.exceptions.some(x=>x.code==="invalid_date"));
  assert.ok(result.exceptions.some(x=>x.code==="currency_mismatch"));
  assert.equal(JSON.stringify(result).includes("row-1"),false);
});

test("unparseable or non-string control totals never pass reconciliation",()=>{
  for(const controlTotal of ["not-money",100.5,"1.234"]){
    const result=profileMigration({manifest:{...manifest,controlTotal},mappings,requiredTargets:["sourceId","amount","date","currency"],rows});
    assert.equal(result.status,"blocked");
    assert.equal(result.controlTotalMatches,false);
    assert.equal(result.sourceControlTotal,null);
  }
});

test("source rows outside the declared period and missing mapping versions are blocked",()=>{
  const outside=profileMigration({manifest,mappings,requiredTargets:["sourceId","amount","date","currency"],rows:[{...rows[0],service_date:"2026-12-01"},rows[1]]});
  assert.equal(outside.status,"blocked");
  assert.ok(outside.exceptions.some(x=>x.code==="date_outside_manifest_period"));
  assert.throws(()=>profileMigration({manifest:{...manifest,mappingVersion:""},mappings,requiredTargets:["sourceId","amount","date","currency"],rows}),/Source manifest/);
});
