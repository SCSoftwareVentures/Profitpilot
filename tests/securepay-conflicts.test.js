import test from "node:test";
import assert from "node:assert/strict";
import {validConflictDeclaration,sameConflictDeclaration} from "../src/securepay-conflicts.js";
const no={clientRequestId:"11111111-1111-4111-8111-111111111111",
 declarationStatus:"no_conflict_declared",conflictCode:null,disclosureReference:null};
const yes={...no,declarationStatus:"potential_conflict",conflictCode:"financial_interest",
 disclosureReference:"disclosure.s4.001"};
test("bounded reviewer self-declaration validates mutually exclusive fields",()=>{
 assert.equal(validConflictDeclaration(no),true);
 assert.equal(validConflictDeclaration(yes),true);
 for(const bad of [{...no,paymentApproved:true},{...no,conflictCode:"other"},
  {...no,declarationStatus:"verified"},{...yes,disclosureReference:null},
  {...yes,conflictCode:"irrelevant"},{...yes,disclosureReference:"<personal detail>"},
  {...no,clientRequestId:"not-uuid"},null,[],{}])
  assert.equal(validConflictDeclaration(bad),false);
});
test("replay detection requires the same self-reported status, code and reference",()=>{
 const row={declaration_status:"potential_conflict",conflict_code:"financial_interest",disclosure_reference:"disclosure.s4.001"};
 assert.equal(sameConflictDeclaration(row,yes),true);
 assert.equal(sameConflictDeclaration(row,{...yes,conflictCode:"other"}),false);
 assert.equal(sameConflictDeclaration(row,{...yes,disclosureReference:"another.ref"}),false);
});
