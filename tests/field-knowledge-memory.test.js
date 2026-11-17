import test from "node:test";
import assert from "node:assert/strict";
import {createKnowledgeEntry,canReadKnowledgeEntry} from "../src/field-knowledge-memory.js";

const base={id:"knowledge-001",tenantId:"tenant-001",scopeRef:"site-Riverside",ownerId:"user-owner",sourceRef:"site-manual-v1",type:"access_instructions",visibility:"internal",confidence:"reported",content:"Synthetic note: use the designated loading entrance during the approved service window.",evidenceRefs:["site-manual-v1"],reviewAt:"2026-12-01",expiresAt:"2027-01-01",asOf:"2026-11-17"};

test("knowledge entries require ownership, scope, source, review and expiry metadata",()=>{
  const entry=createKnowledgeEntry(base);
  assert.equal(entry.state,"current");
  assert.equal(entry.requiresReview,false);
  assert.equal(entry.tenantId,"tenant-001");
  for(const overrides of [{sourceRef:""},{scopeRef:""},{reviewAt:"bad-date"},{expiresAt:"2026-11-01"}])assert.throws(()=>createKnowledgeEntry({...base,...overrides}));
});

test("review-due and expired knowledge are visibly distinguished",()=>{
  assert.equal(createKnowledgeEntry({...base,reviewAt:"2026-11-01"}).state,"review_due");
  assert.equal(createKnowledgeEntry({...base,expiresAt:"2026-11-01"}).state,"expired");
});

test("verified knowledge requires evidence and customer-visible records require a customer scope",()=>{
  assert.throws(()=>createKnowledgeEntry({...base,confidence:"verified",evidenceRefs:[]}),/evidence reference/);
  assert.throws(()=>createKnowledgeEntry({...base,visibility:"customer_visible",customerId:""}),/customer scope/);
  assert.throws(()=>createKnowledgeEntry({...base,visibility:"internal",customerId:"customer-1"}),/only valid/);
});

test("internal knowledge is tenant-scoped",()=>{
  const entry=createKnowledgeEntry(base);
  assert.equal(canReadKnowledgeEntry(entry,{tenantId:"tenant-001",userId:"user-2"}),true);
  assert.equal(canReadKnowledgeEntry(entry,{tenantId:"tenant-002",userId:"user-owner"}),false);
});

test("customer-visible knowledge is restricted to the matching customer in the tenant",()=>{
  const entry=createKnowledgeEntry({...base,visibility:"customer_visible",customerId:"customer-1"});
  assert.equal(canReadKnowledgeEntry(entry,{tenantId:"tenant-001",customerId:"customer-1"}),true);
  assert.equal(canReadKnowledgeEntry(entry,{tenantId:"tenant-001",customerId:"customer-2"}),false);
  assert.equal(canReadKnowledgeEntry(entry,{tenantId:"tenant-002",customerId:"customer-1"}),false);
});

test("restricted knowledge is owner-only except tenant owner/admin roles",()=>{
  const entry=createKnowledgeEntry({...base,visibility:"restricted"});
  assert.equal(canReadKnowledgeEntry(entry,{tenantId:"tenant-001",userId:"user-owner"}),true);
  assert.equal(canReadKnowledgeEntry(entry,{tenantId:"tenant-001",userId:"user-2",roles:["admin"]}),true);
  assert.equal(canReadKnowledgeEntry(entry,{tenantId:"tenant-001",userId:"user-2",roles:["analyst"]}),false);
});

test("unsupported visibility, confidence and malformed actors fail closed",()=>{
  assert.throws(()=>createKnowledgeEntry({...base,visibility:"public"}),/must be explicit/);
  assert.throws(()=>createKnowledgeEntry({...base,confidence:"certain"}),/must be explicit/);
  assert.equal(canReadKnowledgeEntry(createKnowledgeEntry(base),null),false);
});
