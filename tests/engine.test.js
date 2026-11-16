import test from "node:test";
import assert from "node:assert/strict";
import {money,parseCsv,validateInvoiceRows,allocatePayroll,matchInvoice,aggregateMetrics,isIsoDate,normalizePayrollRows} from "../src/engine.js";

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
test("CSV accepts a UTF-8 BOM before the first heading",()=>assert.equal(parseCsv("\uFEFFinvoice_id,site,date,amount\n1,A,2026-11-01,3")[0].invoice_id,"1"));
test("CSV rejects quotes embedded in unquoted fields",()=>assert.throws(()=>parseCsv('a,b\n1,ab"cd'),/quote inside an unquoted field/));
test("CSV rejects data after a closing quoted field",()=>assert.throws(()=>parseCsv('a\n"safe"tail'),/after a closing quote/));
test("CSV preserves newlines inside quoted fields",()=>assert.equal(parseCsv('a,b\n1,"line one\nline two"')[0].b,"line one\nline two"));
test("CSV rejects case-insensitive duplicate headings",()=>assert.throws(()=>parseCsv("Invoice_ID,invoice_id\n1,2"),/duplicate column headings/));
test("CSV rejects non-text input",()=>assert.throws(()=>parseCsv(null),/must be text/));
test("invoice missing required fields is held",()=>assert.equal(validateInvoiceRows([{invoice_id:"1",date:"2026-11-01",amount:"3"}])[0].status,"held"));
test("invoice valid row remains pending human review",()=>assert.equal(validateInvoiceRows([{invoice_id:"1",site:"A",date:"2026-11-01",amount:"3"}])[0].status,"pending_review"));
test("negative invoice is held",()=>assert.equal(validateInvoiceRows([{invoice_id:"1",site:"A",date:"2026-11-01",amount:"-3"}])[0].status,"held"));
test("invoice whitespace-only identity fields are held",()=>assert.equal(validateInvoiceRows([{invoice_id:" ",site:"A",date:"2026-11-01",amount:"3"}])[0].status,"held"));
test("invoice amount rejects non-decimal numeric syntax",()=>assert.equal(validateInvoiceRows([{invoice_id:"1",site:"A",date:"2026-11-01",amount:"0x10"}])[0].status,"held"));
test("invoice amount rejects more than two fractional digits",()=>assert.equal(validateInvoiceRows([{invoice_id:"1",site:"A",date:"2026-11-01",amount:"1.234"}])[0].status,"held"));
test("impossible calendar date is held",()=>assert.equal(validateInvoiceRows([{invoice_id:"1",site:"A",date:"2026-02-31",amount:"3"}])[0].status,"held"));
test("payroll buckets reconcile",()=>assert.equal(allocatePayroll({pool:1000,direct:[{site:"A",amount:400}],approved:[{site:"B",amount:300}],nonSite:200,excluded:50}).reconciles,true));
test("over-allocation is rejected",()=>assert.equal(allocatePayroll({pool:100,direct:[{site:"A",amount:101}]}).reconciles,false));
test("negative allocation is rejected",()=>assert.equal(allocatePayroll({pool:100,direct:[{site:"A",amount:-1}]}).reconciles,false));
test("amount-only match remains low-confidence and unconfirmed",()=>{const r=matchInvoice({amount:100},{id:"c",periodStart:"2026-11-01",periodEnd:"2026-11-30"});assert.equal(r.confidence,"LOW");assert.equal(r.requiresHumanConfirmation,true);assert.equal(r.decision,"candidate");});
test("match candidate always needs human confirmation",()=>assert.equal(matchInvoice({site:"A",date:"2026-11-05",amount:100},{id:"c",site:"A",periodStart:"2026-11-01",periodEnd:"2026-11-30"}).requiresHumanConfirmation,true));
test("metrics aggregate totals and margin",()=>{const r=aggregateMetrics([{revenue:1000,cost:600},{revenue:500,cost:250}]);assert.deepEqual([r.revenue,r.cost,r.contribution,r.margin],[1500,850,650,43.33]);});

test("money rounds decimal half-cents consistently, including negative values",()=>{
  assert.equal(money("1.005"),1.01);
  assert.equal(money("2.675"),2.68);
  assert.equal(money("-1.005"),-1.01);
});
test("money rejects non-finite and malformed inputs",()=>{
  assert.equal(Number.isNaN(money("not-money")),true);
  assert.equal(Number.isNaN(money(Infinity)),true);
});
test("payroll allocation sums decimal amounts without binary floating drift",()=>{
  const result=allocatePayroll({pool:"0.30",direct:[{site:"A",amount:"0.10"},{site:"A",amount:"0.20"}]});
  assert.equal(result.reconciles,true);
  assert.equal(result.direct,0.30);
  assert.equal(result.siteTotals.A,0.30);
});
test("contract aggregation preserves cents over repeated decimal values",()=>{
  const result=aggregateMetrics([{revenue:"0.10",cost:"0.03"},{revenue:"0.20",cost:"0.06"}]);
  assert.deepEqual([result.revenue,result.cost,result.contribution,result.margin],[0.30,0.09,0.21,70]);
});

test("invoice matcher rejects hexadecimal and non-finite amount syntax",()=>{
  assert.equal(matchInvoice({site:"A",date:"2026-11-05",amount:"0x10"},{id:"c",site:"A",periodStart:"2026-11-01",periodEnd:"2026-11-30"}).confidence,"UNMATCHED");
  assert.equal(matchInvoice({site:"A",date:"2026-11-05",amount:"Infinity"},{id:"c",site:"A",periodStart:"2026-11-01",periodEnd:"2026-11-30"}).confidence,"UNMATCHED");
});


test("payroll normalizer emits canonical cents, currency and deterministic row hash",()=>{
  const rows=normalizePayrollRows([{source_row_key:"row-001",amount:"12.3",currency:"aud",employee_name:"Synthetic Person",bank_account:"DO-NOT-RETAIN"}]);
  assert.equal(rows[0].status,"pending_review");
  assert.deepEqual(rows[0].record,{sourceRowKey:"row-001",amount:"12.30",currency:"AUD"});
  assert.equal(rows[0].rowSha256.length,64);
  assert.equal(JSON.stringify(rows[0]).includes("Synthetic Person"),false);
  assert.equal(JSON.stringify(rows[0]).includes("DO-NOT-RETAIN"),false);
});
test("payroll normalizer holds malformed money, currency and unsafe row keys",()=>{
  const rows=normalizePayrollRows([
    {source_row_key:"row-a",amount:"1.234",currency:"AUD"},
    {source_row_key:"row-b",amount:"-1.00",currency:"AUD"},
    {source_row_key:"row-c",amount:"1.00",currency:"AU"},
    {source_row_key:"../employee-name",amount:"1.00",currency:"AUD"}
  ]);
  assert.deepEqual(rows.map(x=>x.status),["held","held","held","held"]);
  assert.ok(rows.every(x=>x.record===null&&x.rowSha256===undefined));
});
test("payroll normalizer holds duplicate source keys in a batch",()=>{
  const rows=normalizePayrollRows([
    {source_row_key:"same",amount:"1.00",currency:"AUD"},
    {source_row_key:"same",amount:"2.00",currency:"AUD"}
  ]);
  assert.equal(rows[0].status,"pending_review");
  assert.equal(rows[1].status,"held");
  assert.match(rows[1].errors[0],/Duplicate/);
});
test("payroll normalizer rejects empty and oversized batches",()=>{
  assert.throws(()=>normalizePayrollRows([]),/1–10000/);
  assert.throws(()=>normalizePayrollRows(Array(10001).fill({})),/1–10000/);
});

test("invoice matcher requires customer, contract, site, service period, currency and tax-basis evidence",()=>{
  const contract={id:"contract-1",customerId:"customer-1",siteId:"site-1",periodStart:"2026-11-01",periodEnd:"2026-11-30",currency:"AUD",taxBasis:"gst_exclusive"};
  const row={customer_id:"customer-1",contract_id:"contract-1",site_id:"site-1",service_period_start:"2026-11-01",service_period_end:"2026-11-30",amount:"100.00",currency:"AUD",tax_basis:"gst_exclusive"};
  const result=matchInvoice(row,contract);
  assert.equal(result.confidence,"HIGH");
  assert.equal(result.requiresHumanConfirmation,true);
  assert.equal(result.decision,"candidate");
  assert.equal(matchInvoice({...row,site_id:undefined},contract).confidence,"LOW");
  assert.equal(matchInvoice({...row,currency:"NZD"},contract).evidence.currency,false);
  assert.equal(matchInvoice({...row,tax_basis:"unknown"},contract).evidence.taxBasis,false);
});
test("invoice validation uses strict decimal syntax without Number coercion",()=>{
  const base={invoice_id:"1",site:"A",date:"2026-11-01"};
  for(const amount of ["0","0.00","1e2","0x10","1,000.00","1.234","Infinity","-1"])
    assert.equal(validateInvoiceRows([{...base,amount}])[0].status,"held",amount);
  assert.equal(validateInvoiceRows([{...base,amount:"100.00"}])[0].status,"pending_review");
});

test("money rejects amounts whose cent representation cannot be safely returned as a JavaScript number",()=>{
  assert.equal(Number.isNaN(money("90071992547409.92")),true);
  assert.equal(money("90071992547409.91"),90071992547409.9);
});

test("contract aggregation blocks mixed currencies, tax bases and reporting periods",()=>{
  const common={currency:"AUD",taxBasis:"gst_exclusive",periodStart:"2026-11-01",periodEnd:"2026-11-30"};
  const mixedCurrency=aggregateMetrics([{...common,revenue:100,cost:50},{...common,currency:"NZD",revenue:100,cost:50}]);
  assert.equal(mixedCurrency.complete,false);
  assert.equal(mixedCurrency.contribution,null);
  const mixedTax=aggregateMetrics([{...common,revenue:100,cost:50},{...common,taxBasis:"gst_inclusive",revenue:100,cost:50}]);
  assert.equal(mixedTax.complete,false);
  const mixedPeriod=aggregateMetrics([{...common,revenue:100,cost:50},{...common,periodStart:"2026-10-01",periodEnd:"2026-10-31",revenue:100,cost:50}]);
  assert.equal(mixedPeriod.complete,false);
  assert.equal(aggregateMetrics([{...common,revenue:100,cost:50},{...common,revenue:100,cost:50}]).contribution,100);
});
