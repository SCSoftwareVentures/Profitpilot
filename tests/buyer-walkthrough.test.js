import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {join,resolve} from "node:path";
import {fileURLToPath} from "node:url";
import {runInNewContext} from "node:vm";
import {createBuyerDemoState,applyBuyerDemoDecision,buildBuyerDemoSnapshot,
 exportBuyerDemoEvidence,BUYER_SCENARIO_VERSION} from "../src/buyer-walkthrough-core.js";

const root=resolve(fileURLToPath(new URL("..",import.meta.url)));
const generated=()=>readFileSync(join(root,"demo/buyer-walkthrough.html"),"utf8");
const shell=()=>readFileSync(join(root,"demo/buyer-walkthrough.shell.html"),"utf8");
const core=()=>readFileSync(join(root,"src/buyer-walkthrough-core.js"),"utf8");
const findContract=(s,id)=>s.contracts.find(x=>x.id===id);

test("B1 starts as genuinely incomplete: do not present portfolio totals as verified or zero",()=>{
 const state=createBuyerDemoState(),s=buildBuyerDemoSnapshot(state);
 assert.equal(s.version,BUYER_SCENARIO_VERSION);
 assert.equal(s.contractCount,3);
 assert.deepEqual(s.coverage,{invoiceCovered:2,payrollCovered:2,readyCount:1,total:3});
 assert.equal(s.totals.billedCents,null);
 assert.equal(s.totals.costCents,null);
 assert.equal(s.totals.contributionCents,null);
 assert.equal(s.totals.confirmedBilledPartialCents,4_450_000);
 assert.equal(s.totals.unallocatedPayrollCents,60_000);
 assert.equal(s.totals.payrollPoolCents,2_680_000);
 assert.equal(s.totals.allocatedPayrollCents,2_620_000);
 assert.equal(findContract(s,"CN-103").contributionCents,620_000);
 assert.equal(findContract(s,"CN-103").variationCandidateCents,200_000);
 assert.equal(s.exceptions.length,3);
 assert.equal(s.syntheticOnly,true);
 assert.equal(s.externallyValidated,false);
 assert.equal(s.paymentAuthority,false);
});
test("B1 confirming invoice releases billed total, never releases unsupported contribution",()=>{
 const start=createBuyerDemoState();
 const next=applyBuyerDemoDecision(start,"confirm_invoice");
 const snap=buildBuyerDemoSnapshot(next);
 assert.equal(start.invoice,"held");
 assert.equal(next.invoice,"confirmed");
 assert.equal(snap.totals.billedCents,4_500_000);
 assert.equal(snap.totals.costCents,null);
 assert.equal(snap.totals.contributionCents,null);
 assert.equal(snap.exceptions.some(x=>x.id==="EX-INVOICE-1"),false);
 assert.equal(snap.totals.unallocatedPayrollCents,60_000);
 assert.equal(snap.decisionLog.length,1);
});
test("B1 allocating payroll never loses residual or releases unsupported invoices",()=>{
 const allocated=applyBuyerDemoDecision(createBuyerDemoState(),"allocate_payroll");
 const snap=buildBuyerDemoSnapshot(allocated);
 assert.equal(snap.totals.billedCents,null);
 assert.equal(snap.totals.costCents,3_130_000);
 assert.equal(snap.totals.contributionCents,null);
 assert.equal(snap.totals.payrollPoolCents,snap.totals.allocatedPayrollCents);
 assert.equal(snap.totals.unallocatedPayrollCents,0);
 assert.equal(findContract(snap,"CN-102").allocatedPayrollCents,760_000);
 assert.equal(snap.exceptions.some(x=>x.id==="EX-PAYROLL-1"),false);
});
test("B1 both approvals produce deterministic complete cents bridge regardless of review order",()=>{
 const left=applyBuyerDemoDecision(applyBuyerDemoDecision(createBuyerDemoState(),"confirm_invoice"),"allocate_payroll");
 const right=applyBuyerDemoDecision(applyBuyerDemoDecision(createBuyerDemoState(),"allocate_payroll"),"confirm_invoice");
 for(const state of [left,right]){
  const snap=buildBuyerDemoSnapshot(state);
  assert.deepEqual(snap.coverage,{invoiceCovered:3,payrollCovered:3,readyCount:3,total:3});
  assert.equal(snap.totals.billedCents,4_500_000);
  assert.equal(snap.totals.costCents,3_130_000);
  assert.equal(snap.totals.contributionCents,1_370_000);
  assert.equal(snap.totals.billedCents-snap.totals.costCents,snap.totals.contributionCents);
  assert.equal(snap.exceptions.length,1);
  assert.equal(snap.exceptions[0].id,"EX-VARIATION-1");
  assert.equal(snap.exceptions[0].action,null);
  assert.equal(snap.totals.billedCents,snap.totals.contractBaselineCents);
  assert.equal(snap.totals.payrollPoolCents,snap.totals.allocatedPayrollCents);
 }
 assert.deepEqual(buildBuyerDemoSnapshot(left).totals,buildBuyerDemoSnapshot(right).totals);
});
test("B1 unsupported, duplicate and forged reviewer decisions are rejected without mutation",()=>{
 const state=createBuyerDemoState();
 assert.throws(()=>applyBuyerDemoDecision(state,"pay_out"));
 assert.deepEqual(state,createBuyerDemoState());
 const once=applyBuyerDemoDecision(state,"confirm_invoice");
 assert.throws(()=>applyBuyerDemoDecision(once,"confirm_invoice"));
 assert.throws(()=>buildBuyerDemoSnapshot({...state,invoice:"confirmed"}),/Decision log/);
 assert.throws(()=>buildBuyerDemoSnapshot({...state,log:[{action:"confirm_invoice"}]}),/decision log/i);
 assert.throws(()=>buildBuyerDemoSnapshot({...state,log:[{sequence:1,action:"pay_out",reference:"X",actor:"Fictional reviewer",note:"x"}]}));
 assert.equal(exportBuyerDemoEvidence(state).snapshot.totals.contributionCents,null);
});
test("B1 export is explicitly synthetic, traceable and excludes real identity/payment claims",()=>{
 const state=applyBuyerDemoDecision(createBuyerDemoState(),"confirm_invoice");
 const report=exportBuyerDemoEvidence(state);
 assert.equal(report.format,"profitpilot.buyer-demo-evidence.v1");
 assert.match(report.disclaimer,/Fictional browser-only/);
 assert.match(report.sourceBasis,/synthetic/);
 assert.match(report.decisionAuthority,/Simulated/);
 assert.equal(report.snapshot.externallyValidated,false);
 assert.equal(report.snapshot.paymentAuthority,false);
 assert.equal(report.snapshot.decisionLog[0].reference,"INV-R-204");
 assert.equal(JSON.stringify(report).includes("PRIVATE KEY"),false);
});
test("B1 standalone page is deterministic, dependency-free and prohibits network connections",()=>{
 const source=core(),template=shell(),html=generated();
 const standalone=source.replace(/^export (?=(?:const|function)\b)/gm,"");
 assert.equal(html,template.replace("/*__BUYER_DEMO_CORE__*/",standalone));
 assert.match(html,/connect-src 'none'/);
 assert.match(html,/default-src 'none'/);
 assert.match(html,/user|customer/i);
 assert.match(html,/Not established/i);
 assert.doesNotMatch(html,/<script\b[^>]*\bsrc\s*=/i);
 assert.doesNotMatch(html,/https?:\/\//i);
 assert.doesNotMatch(html,/\bfetch\s*\(/);
 assert.doesNotMatch(html,/\blocalStorage\b|\bsessionStorage\b/);
 assert.doesNotMatch(html,/^\s*import\s/m);
 assert.doesNotMatch(html,/document\.write\s*\(/);
});
class FakeElement{
 constructor(tag){this.tag=tag;this.children=[];this._text="";this.listeners={};this.className="";}
 set textContent(value){this._text=String(value);this.children=[];}
 get textContent(){return this._text+this.children.map(x=>x.textContent??"").join("");}
 append(...nodes){this.children.push(...nodes);}
 get firstChild(){return this.children[0]??null;}
 removeChild(node){this.children.splice(this.children.indexOf(node),1);}
 setAttribute(name,value){this[name]=value;}
 addEventListener(name,fn){this.listeners[name]=fn;}
 click(){this.listeners.click?.();}
 remove(){}
}
const visit=(root,predicate)=>{
 if(predicate(root))return root;
 for(const child of root.children){
  const found=visit(child,predicate);if(found)return found;
 }
 return null;
};
test("B1 embedded DOM walkthrough actually changes displayed financial results on simulated decisions",()=>{
 const html=generated();
 const code=html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
 assert.ok(code,"standalone inline script exists");
 const selectors=["reset","export","kpis","coverage","portfolio-status",
  "exceptions","exception-count","decision-log","contract-rows","live-status"];
 const nodes=new Map(selectors.map(id=>["#"+id,new FakeElement("section")]));
 const document={
  createElement:tag=>new FakeElement(tag),
  querySelector:selector=>{
   const node=nodes.get(selector);
   if(!node)throw Error("Unexpected selector "+selector);
   return node;
  },
  body:new FakeElement("body")
 };
 const context={document,Intl,Blob,URL:{createObjectURL:()=> "blob:test",revokeObjectURL:()=>{}}};
 runInNewContext(code,context,{timeout:2000,filename:"buyer-walkthrough.html"});
 const kpis=nodes.get("#kpis");
 assert.equal(kpis.children.length,3);
 assert.match(kpis.children[0].textContent,/Unavailable/);
 assert.match(kpis.children[2].textContent,/Unavailable/);
 let invoice=visit(nodes.get("#exceptions"),x=>x.tag==="button"&&x.textContent.includes("invoice-match"));
 assert.ok(invoice);invoice.click();
 assert.match(kpis.children[0].textContent,/\$45,000\.00/);
 assert.match(kpis.children[2].textContent,/Unavailable/);
 let payroll=visit(nodes.get("#exceptions"),x=>x.tag==="button"&&x.textContent.includes("payroll"));
 assert.ok(payroll);payroll.click();
 assert.match(kpis.children[1].textContent,/\$31,300\.00/);
 assert.match(kpis.children[2].textContent,/\$13,700\.00/);
 assert.match(nodes.get("#decision-log").textContent,/Simulated/);
 nodes.get("#reset").click();
 assert.match(kpis.children[2].textContent,/Unavailable/);
});
