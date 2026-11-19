import test from "node:test";
import assert from "node:assert/strict";
import {money,parseCsv,validateInvoiceRows,allocatePayroll,matchInvoice,aggregateMetrics,isIsoDate,payrollCents,validatePayrollRows,reconcilePayroll} from "../src/engine.js";

test("money uses cent precision",()=>assert.equal(money(10.126),10.13));
test("ISO date accepts a valid calendar date",()=>assert.equal(isIsoDate("2026-11-16"),true));
test("ISO date accepts leap day only in leap years",()=>{assert.equal(isIsoDate("2024-02-29"),true);assert.equal(isIsoDate("2025-02-29"),false);});
test("ISO date rejects impossible and malformed dates",()=>{assert.equal(isIsoDate("2026-02-31"),false);assert.equal(isIsoDate("16-11-2026"),false);});
test("CSV parses standard records",()=>assert.equal(parseCsv("a,b\n1,2").length,1));
test("CSV supports quoted commas",()=>assert.equal(parseCsv('a,b\n1,"two,three"')[0].b,"two,three"));
test("CSV supports escaped quotes",()=>assert.equal(parseCsv('a\n"say ""hi"""')[0].a,'say "hi"'));
test("CSV rejects unclosed quote",()=>assert.throws(()=>parseCsv('a\n"bad')));
test("CSV rejects duplicate headings",()=>assert.throws(()=>parseCsv("a,a\n1,2")));
test("CSV rejects inconsistent row widths",()=>assert.throws(()=>parseCsv("a,b\n1")));
test("CSV rejects empty headings",()=>assert.throws(()=>parseCsv(",b\n1,2")));
test("CSV handles CRLF",()=>assert.equal(parseCsv("a,b\r\n1,2\r\n").length,1));
test("invoice missing required fields is held",()=>assert.equal(validateInvoiceRows([{invoice_id:"1",date:"2026-11-01",amount:"3"}])[0].status,"held"));
test("invoice valid row remains pending human review",()=>assert.equal(validateInvoiceRows([{invoice_id:"1",site:"A",date:"2026-11-01",amount:"3"}])[0].status,"pending_review"));
test("negative invoice is held",()=>assert.equal(validateInvoiceRows([{invoice_id:"1",site:"A",date:"2026-11-01",amount:"-3"}])[0].status,"held"));
test("impossible calendar date is held",()=>assert.equal(validateInvoiceRows([{invoice_id:"1",site:"A",date:"2026-02-31",amount:"3"}])[0].status,"held"));
test("payroll buckets reconcile",()=>assert.equal(allocatePayroll({pool:1000,direct:[{site:"A",amount:400}],approved:[{site:"B",amount:300}],nonSite:200,excluded:50}).reconciles,true));
test("over-allocation is rejected",()=>assert.equal(allocatePayroll({pool:100,direct:[{site:"A",amount:101}]}).reconciles,false));
test("negative allocation is rejected",()=>assert.equal(allocatePayroll({pool:100,direct:[{site:"A",amount:-1}]}).reconciles,false));
test("amount-only match is unmatched",()=>assert.equal(matchInvoice({amount:100},{site:"A",periodStart:"2026-11-01",periodEnd:"2026-11-30"}).confidence,"UNMATCHED"));
test("match candidate always needs human confirmation",()=>assert.equal(matchInvoice({site:"A",date:"2026-11-05",amount:100},{id:"c",site:"A",periodStart:"2026-11-01",periodEnd:"2026-11-30"}).requiresHumanConfirmation,true));
test("metrics aggregate totals and margin",()=>{const r=aggregateMetrics([{revenue:1000,cost:600},{revenue:500,cost:250}]);assert.deepEqual([r.revenue,r.cost,r.contribution,r.margin],[1500,850,650,43.33]);});

test("payroll decimal parser rejects coercion and fractional cents",()=>{
 assert.equal(payrollCents("123.45"),12345);
 for(const x of [123.45,"1e2","1.001","-1","1,000","NaN","1000000000000"])assert.equal(payrollCents(x),null);
});
const payrollPeriod={periodStart:"2026-02-01",periodEnd:"2026-02-28"};
const payrollRow={source_ref:"ledger:1",amount:"100.01",currency:"AUD",period_start:payrollPeriod.periodStart,period_end:payrollPeriod.periodEnd};
test("payroll holds duplicate source IDs and mismatched period",()=>{
 assert.ok(validatePayrollRows([payrollRow,payrollRow],payrollPeriod).every(r=>r.errors.length));
 assert.equal(validatePayrollRows([{...payrollRow,period_end:"2026-03-01"}],payrollPeriod)[0].status,"held");
});
test("exact reconciliation preserves residual and rejects duplicates",()=>{
 const rows=validatePayrollRows([payrollRow,{...payrollRow,source_ref:"ledger:2",amount:"0.09"}],payrollPeriod);
 const plan=[{rowNumber:1,bucket:"direct",siteId:"site",reason:"Verified coding"}];
 const result=reconcilePayroll(rows,plan,"100.10","AUD");
 assert.equal(result.buckets.direct,"100.01");assert.equal(result.buckets.unallocated,"0.09");
 assert.throws(()=>reconcilePayroll(rows,plan,"100.11","AUD"),/control total/);
 assert.throws(()=>reconcilePayroll(rows,[...plan,...plan],"100.10","AUD"),/Duplicate/);
 assert.throws(()=>reconcilePayroll(rows,plan,"100.10","USD"),/currency/);
});
