// B1. Deterministic, synthetic buyer-walkthrough domain engine.
// Not a financial ledger. Never accept uploaded or live tenant/customer data.
export const BUYER_SCENARIO_VERSION="profitpilot.buyer-demo.b1.v1";
const SCENARIO=[
 {id:"CN-101",name:"Riverside Offices",period:"Oct 2026",contractSource:"CON-R-101",
  invoiceSource:"INV-R-204",payrollSource:"PAY-R-OCT",materialSource:"MAT-R-OCT",
  baselineCents:1500000,confirmedInvoiceCents:1450000,heldInvoiceCents:50000,
  payrollPoolCents:920000,allocatedPayrollCents:920000,unallocatedPayrollCents:0,
  materialsCents:130000,unapprovedVariationCents:0},
 {id:"CN-102",name:"Northside Retail",period:"Oct 2026",contractSource:"CON-N-102",
  invoiceSource:"INV-N-115",payrollSource:"PAY-N-OCT",materialSource:"MAT-N-OCT",
  baselineCents:1200000,confirmedInvoiceCents:1200000,heldInvoiceCents:0,
  payrollPoolCents:760000,allocatedPayrollCents:700000,unallocatedPayrollCents:60000,
  materialsCents:140000,unapprovedVariationCents:0},
 {id:"CN-103",name:"Harbour Strata",period:"Oct 2026",contractSource:"CON-H-103",
  invoiceSource:"INV-H-305",payrollSource:"PAY-H-OCT",materialSource:"MAT-H-OCT",
  baselineCents:1800000,confirmedInvoiceCents:1800000,heldInvoiceCents:0,
  payrollPoolCents:1000000,allocatedPayrollCents:1000000,unallocatedPayrollCents:0,
  materialsCents:180000,unapprovedVariationCents:200000}
];
const ACTIONS={
 confirm_invoice:{field:"invoice",from:"held",to:"confirmed",
  reference:"INV-R-204",label:"Simulated human invoice-match confirmation"},
 allocate_payroll:{field:"payroll",from:"unallocated",to:"allocated",
  reference:"PAY-N-OCT",label:"Simulated payroll residual allocation"}
};
const exact=(o,keys)=>o&&typeof o==="object"&&!Array.isArray(o)&&
 Object.keys(o).length===keys.length&&keys.every(x=>Object.hasOwn(o,x));
const sum=(values)=>values.reduce((a,b)=>a+b,0);
function assertState(state){
 if(!exact(state,["invoice","payroll","log"])||
  !["held","confirmed"].includes(state.invoice)||
  !["unallocated","allocated"].includes(state.payroll)||
  !Array.isArray(state.log)||state.log.length>2)throw Error("Invalid buyer demo state");
 const seen=new Set();
 for(let i=0;i<state.log.length;i++){
  const event=state.log[i],def=ACTIONS[event?.action];
  if(!def||seen.has(event.action)||!exact(event,["sequence","action","reference","actor","note"])||
   event.sequence!==i+1||event.reference!==def.reference||
   event.actor!=="Fictional reviewer"||event.note!==def.label)
   throw Error("Invalid buyer decision log");
  seen.add(event.action);
 }
 if((state.invoice==="confirmed")!==seen.has("confirm_invoice")||
  (state.payroll==="allocated")!==seen.has("allocate_payroll"))
  throw Error("Decision log does not match evidence state");
}
export function createBuyerDemoState(){
 return {invoice:"held",payroll:"unallocated",log:[]};
}
export function applyBuyerDemoDecision(state,action){
 assertState(state);
 const definition=ACTIONS[action];
 if(!definition||state[definition.field]!==definition.from)
  throw Error("Decision unavailable, already applied or unsupported");
 const next={invoice:state.invoice,payroll:state.payroll,
  log:state.log.map(x=>({...x}))};
 next[definition.field]=definition.to;
 next.log.push({sequence:next.log.length+1,action,reference:definition.reference,
  actor:"Fictional reviewer",note:definition.label});
 assertState(next);
 return next;
}
export function buildBuyerDemoSnapshot(state){
 assertState(state);
 const contracts=SCENARIO.map(c=>{
  if(c.payrollPoolCents!==c.allocatedPayrollCents+c.unallocatedPayrollCents)
   throw Error("Payroll pool does not reconcile");
  const invoiceComplete=c.heldInvoiceCents===0||
   (c.id==="CN-101"&&state.invoice==="confirmed");
  const payrollComplete=c.unallocatedPayrollCents===0||
   (c.id==="CN-102"&&state.payroll==="allocated");
  const billedCents=c.confirmedInvoiceCents+(invoiceComplete?c.heldInvoiceCents:0);
  const outstandingInvoiceCents=invoiceComplete?0:c.heldInvoiceCents;
  const allocatedPayrollCents=c.allocatedPayrollCents+
   (payrollComplete?c.unallocatedPayrollCents:0);
  const payrollResidualCents=payrollComplete?0:c.unallocatedPayrollCents;
  const costCents=allocatedPayrollCents+c.materialsCents;
  const ready=invoiceComplete&&payrollComplete;
  const contributionCents=ready?billedCents-costCents:null;
  return {id:c.id,name:c.name,period:c.period,
   contractSource:c.contractSource,invoiceSource:c.invoiceSource,
   payrollSource:c.payrollSource,materialSource:c.materialSource,
   baselineCents:c.baselineCents,billedCents,invoiceReady:invoiceComplete,payrollReady:payrollComplete,
   outstandingInvoiceCents,payrollPoolCents:c.payrollPoolCents,
   allocatedPayrollCents,payrollResidualCents,materialsCents:c.materialsCents,
   costCents:payrollComplete?costCents:null,ready,contributionCents,
   variationCandidateCents:c.unapprovedVariationCents,
   varianceToBaselineCents:invoiceComplete?billedCents-c.baselineCents:null,
   sourceIdentityIndependentlyVerified:false};
 });
 const pending=[];
 const river=contracts[0],north=contracts[1],harbour=contracts[2];
 if(!river.invoiceReady)pending.push({id:"EX-INVOICE-1",severity:"Needs review",
  title:"Unmatched invoice amount",site:river.name,source:river.invoiceSource,
  amountCents:river.outstandingInvoiceCents,action:"confirm_invoice",
  detail:"A fictional $500 invoice candidate is held until a simulated reviewer confirms its match."});
 if(!north.payrollReady)pending.push({id:"EX-PAYROLL-1",severity:"Needs review",
  title:"Unallocated payroll residual",site:north.name,source:north.payrollSource,
  amountCents:north.payrollResidualCents,action:"allocate_payroll",
  detail:"A fictional $600 payroll pool residual must be explicitly assigned; it cannot disappear from total payroll."});
 pending.push({id:"EX-VARIATION-1",severity:"Excluded",
  title:"Unapproved variation candidate",site:harbour.name,source:harbour.contractSource,
  amountCents:harbour.variationCandidateCents,action:null,
  detail:"The fictional $2,000 variation is not approved. It cannot be counted as billed value or authorised by this demo."});
 const invoiceCovered=contracts.filter(x=>x.invoiceReady).length;
 const payrollCovered=contracts.filter(x=>x.payrollResidualCents===0).length;
 const readyCount=contracts.filter(x=>x.ready).length;
 const allInvoices=invoiceCovered===contracts.length;
 const allCosts=payrollCovered===contracts.length;
 const grossConfirmedCents=sum(contracts.map(x=>x.billedCents));
 const contractBaselineCents=sum(contracts.map(x=>x.baselineCents));
 const payrollPoolCents=sum(contracts.map(x=>x.payrollPoolCents));
 const allocatedPayrollCents=sum(contracts.map(x=>x.allocatedPayrollCents));
 const unallocatedPayrollCents=sum(contracts.map(x=>x.payrollResidualCents));
 if(payrollPoolCents!==allocatedPayrollCents+unallocatedPayrollCents)
  throw Error("Portfolio payroll reconciliation failed");
 const costCents=allCosts?sum(contracts.map(x=>x.costCents)):null;
 const billedCents=allInvoices?grossConfirmedCents:null;
 const contributionCents=billedCents!==null&&costCents!==null?
  billedCents-costCents:null;
 return {version:BUYER_SCENARIO_VERSION,currency:"AUD",
  period:"October 2026",syntheticOnly:true,
  externallyValidated:false,paymentAuthority:false,
  contractCount:contracts.length,
  coverage:{invoiceCovered,payrollCovered,readyCount,total:contracts.length},
  totals:{billedCents,costCents,contributionCents,contractBaselineCents,
   confirmedBilledPartialCents:grossConfirmedCents,payrollPoolCents,
   allocatedPayrollCents,unallocatedPayrollCents},
  contracts,exceptions:pending,
  decisionLog:state.log.map(x=>({...x}))};
}
export function exportBuyerDemoEvidence(state){
 const snapshot=buildBuyerDemoSnapshot(state);
 return {format:"profitpilot.buyer-demo-evidence.v1",
  disclaimer:"Fictional browser-only demonstration. No real source, identity, payroll, financial or payment authority verified.",
  snapshot,sourceBasis:"Hand-authored synthetic fixtures only",
  calculationBasis:"Integer Australian dollar cents; withheld aggregate financial metrics until their required source coverage is complete",
  decisionAuthority:"Simulated reviewer interaction in the browser; no authenticated or persisted approval",
  generatedBy:"ProfitPilot buyer walkthrough B1"};
}
