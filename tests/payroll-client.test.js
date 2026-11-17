import test from "node:test";
import assert from "node:assert/strict";
import {createPayrollClient,PayrollRequestError} from "../src/payroll-client.js";
const tenant="11111111-1111-4111-8111-111111111111";
const batch="22222222-2222-4222-8222-222222222222";
const pool="33333333-3333-4333-8333-333333333333";
const run="44444444-4444-4444-8444-444444444444";
const site="55555555-5555-4555-8555-555555555555";
function fixture(reply={sourceType:"payroll",batchId:batch},status=200){
 const calls=[],tokens=[];
 const client=createPayrollClient({getAccessToken:async opts=>{tokens.push(opts.fresh);return "synthetic.jwt.token";},
 fetchImpl:async(path,opts)=>{calls.push({path,opts});return new Response(JSON.stringify(reply),{status});}});
 return {client,calls,tokens};
}
test("review uses tenant scope, header authentication and no cache or redirect",async()=>{
 const {client,calls,tokens}=fixture();
 await client.review(tenant,batch,{offset:50,limit:25});
 assert.equal(calls[0].path,`/v1/tenants/${tenant}/imports/${batch}/review?offset=50&limit=25`);
 assert.equal(calls[0].opts.method,"GET");
 assert.equal(calls[0].opts.headers.Authorization,"Bearer synthetic.jwt.token");
 assert.equal(calls[0].opts.cache,"no-store");
 assert.equal(calls[0].opts.credentials,"omit");
 assert.equal(calls[0].opts.redirect,"error");
 assert.equal(calls[0].opts.referrerPolicy,"no-referrer");
 assert.deepEqual(tokens,[false]);
});
test("review rejects non-payroll and mismatched batch results",async()=>{
 for(const reply of [{sourceType:"customer_invoice",batchId:batch},{sourceType:"payroll",batchId:pool}]){
  await assert.rejects(fixture(reply).client.review(tenant,batch),e=>e instanceof PayrollRequestError&&e.status===422);
 }
});
test("review and mutations reject unsafe IDs, invalid pagination and implicit approvals",async()=>{
 const {client,calls,tokens}=fixture();
 await assert.rejects(client.review("../external",batch),TypeError);
 await assert.rejects(client.review(tenant,batch,{limit:101}),TypeError);
 assert.throws(()=>client.decide(tenant,batch,1,{decision:"candidate",reason:"Explicit review"}),TypeError);
 assert.throws(()=>client.reconcile(tenant,batch,{declaredTotal:12,sourceReference:"ref",reason:"review"}),TypeError);
 assert.throws(()=>client.confirm(tenant,pool,run,{reason:"approval"}),TypeError);
 assert.equal(calls.length,0);assert.equal(tokens.length,0);
});
test("decision, reconciliation and confirmation request fresh authentication",async()=>{
 const {client,calls,tokens}=fixture();
 await client.decide(tenant,batch,2,{decision:"rejected",reason:"Source rejected"});
 await client.reconcile(tenant,batch,{declaredTotal:"25.10",sourceReference:"REF-1",reason:"Source reconciled"});
 await client.confirm(tenant,pool,run,{reason:"Independent review",acknowledged:true});
 assert.deepEqual(tokens,[true,true,true]);
 assert.deepEqual(calls.map(x=>x.path),[`/v1/tenants/${tenant}/imports/${batch}/payroll/rows/2/decision`,`/v1/tenants/${tenant}/imports/${batch}/payroll/pool`,`/v1/tenants/${tenant}/payroll/pools/${pool}/allocations/${run}/confirm`]);
 assert.deepEqual(JSON.parse(calls[1].opts.body),{declaredTotal:"25.10",sourceReference:"REF-1",reason:"Source reconciled"});
 assert.deepEqual(JSON.parse(calls[2].opts.body),{reason:"Independent review"});
 assert.ok(calls.every(x=>x.opts.method==="POST"));
});
test("draft preserves exact decimal amounts and validates bucket/site binding",async()=>{
 const {client,calls,tokens}=fixture();
 const line={bucketType:"direct",siteId:site,amount:"10.01",sourceReference:"REF-2"};
 for(const invalid of [{...line,amount:"0.00"},{...line,amount:"1e2"},{...line,siteId:null},{...line,bucketType:"non_site"}]){
  assert.throws(()=>client.draft(tenant,pool,{lines:[invalid],reason:"draft"}),TypeError);
 }
 await client.draft(tenant,pool,{lines:[line],reason:"draft"});
 assert.deepEqual(JSON.parse(calls[0].opts.body),{lines:[line],reason:"draft"});
 assert.deepEqual(tokens,[false]);
});
test("failed mutation never retries or leaks server-provided error detail",async()=>{
 const {client,calls}=fixture({error:"private source detail"},409);
 await assert.rejects(client.confirm(tenant,pool,run,{reason:"Independent review",acknowledged:true}),e=>e.status===409&&!e.message.includes("private"));
 assert.equal(calls.length,1);
 let count=0;
 const broken=createPayrollClient({getAccessToken:async()=>"synthetic.jwt.token",fetchImpl:async()=>{count++;throw new Error("secret token");}});
 await assert.rejects(broken.confirm(tenant,pool,run,{reason:"Independent review",acknowledged:true}),e=>e.status===0&&e.message.includes("uncertain")&&!e.message.includes("secret"));
 assert.equal(count,1);
});
test("missing credentials prevent any request",async()=>{
 let count=0;
 const client=createPayrollClient({getAccessToken:async()=>null,fetchImpl:async()=>{count++;}});
 await assert.rejects(client.review(tenant,batch),e=>e.status===401);
 assert.equal(count,0);
});

test("contribution reports use fixed tenant routes and server-calculated inputs only",async()=>{
 const {client,calls,tokens}=fixture();
 assert.throws(()=>client.createContributionReport(tenant,{contractId:batch,siteId:site,periodStart:"2026-02-14",periodEnd:"2026-02-01"}),TypeError);
 await client.createContributionReport(tenant,{contractId:batch,siteId:site,periodStart:"2026-02-01",periodEnd:"2026-02-14",revenue:"999999"});
 await client.readContributionReport(tenant,run);
 assert.deepEqual(JSON.parse(calls[0].opts.body),{contractId:batch,siteId:site,periodStart:"2026-02-01",periodEnd:"2026-02-14"});
 assert.equal(calls[0].path,`/v1/tenants/${tenant}/calculations`);
 assert.equal(calls[1].path,`/v1/tenants/${tenant}/calculations/${run}`);
 assert.equal(calls[1].opts.cache,"no-store");assert.deepEqual(tokens,[false,false]);
});

test("expense confirmation requires explicit classification, duplicate review and fresh MFA",async()=>{
 const {client,calls,tokens}=fixture();
 assert.throws(()=>client.confirmDeliveryExpense(tenant,run,{reason:"Reviewed",costCategory:"supplier",payrollOverlapReviewed:true}),TypeError);
 await client.confirmDeliveryExpense(tenant,run,{reason:"Reviewed",costCategory:"supplier",payrollOverlapReviewed:true,duplicateExpenseReviewed:true});
 assert.equal(calls[0].path,`/v1/tenants/${tenant}/matches/${run}/decision`);
 assert.deepEqual(tokens,[true]);assert.deepEqual(JSON.parse(calls[0].opts.body),{decision:"confirmed",reason:"Reviewed",costCategory:"supplier",payrollOverlapReviewed:true,duplicateExpenseReviewed:true});
});

test("invoice workflow uses fixed routes, explicit source review and MFA",async()=>{
 const {client,calls,tokens}=fixture();
 const manifest=[{invoiceNumber:"INV-1",total:"10.00",lineCount:1}];
 assert.throws(()=>client.prepareInvoices(tenant,batch,{manifest,expectedRowCount:1,reason:"Review",sourceReviewed:false}),TypeError);
 assert.throws(()=>client.prepareInvoices(tenant,batch,{manifest:[{...manifest[0],total:10}],expectedRowCount:1,reason:"Review",sourceReviewed:true}),TypeError);
 await client.prepareInvoices(tenant,batch,{manifest,expectedRowCount:1,reason:"Review",sourceReviewed:true});
 await client.decideInvoiceMatch(tenant,run,{decision:"confirmed",expectedDirection:"customer",reason:"Review",acknowledged:true,costCategory:"supplier"});
 assert.deepEqual(tokens,[true,true]);
 assert.deepEqual(calls.map(c=>c.path),["/v1/tenants/"+tenant+"/imports/"+batch+"/invoices/prepare","/v1/tenants/"+tenant+"/matches/"+run+"/decision"]);
 assert.deepEqual(JSON.parse(calls[1].opts.body),{decision:"confirmed",expectedDirection:"customer",reason:"Review"});
 assert.throws(()=>client.decideInvoiceMatch(tenant,run,{decision:"confirmed",expectedDirection:"supplier",reason:"Review",acknowledged:true,costCategory:"supplier"}),TypeError);
});
test("invoice candidate list fails closed for wrong batch, duplicate IDs and unknown direction",async()=>{
 const item={matchId:run,direction:"customer",decision:"candidate"};
 const result={batchId:batch,items:[item],externallyVerified:false};
 for(const reply of [{...result,batchId:site},{...result,items:[item,item]},{...result,items:[{...item,direction:"unknown"}]}])await assert.rejects(fixture(reply).client.invoiceCandidates(tenant,batch),e=>e.status===422);
 const f=fixture(result);assert.deepEqual(await f.client.invoiceCandidates(tenant,batch),result);assert.deepEqual(f.tokens,[true]);
});
