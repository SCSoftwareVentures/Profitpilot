import {isIsoDate,money} from "./engine.js";

const VALUE_EVENT_TYPES=new Set(["proposed","quoted","contractually_accepted","variation_approved","delivered","customer_accepted","invoiced","credited","refunded"]);
const OFFSET_TIMESTAMP=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;
const TOTAL_TYPES=["proposed","quoted","contractually_accepted","variation_approved","delivered","customer_accepted","invoiced","credited","refunded"];

function cents(value){
  const canonical=money(value);
  if(canonical===null)return null;
  const negative=canonical.startsWith("-");
  const unsigned=negative?canonical.slice(1):canonical;
  const [whole,fraction=""]=unsigned.split(".");
  const amount=BigInt(whole)*100n+BigInt(fraction.padEnd(2,"0"));
  return negative?-amount:amount;
}
function decimal(value){
  const negative=value<0n,absolute=negative?-value:value;
  return (negative?"-":"")+(absolute/100n).toString()+"."+(absolute%100n).toString().padStart(2,"0");
}
function text(value,label,max=255){
  if(typeof value!=="string"||!value.trim()||value.trim().length>max)throw new TypeError(label+" is required");
  return value.trim();
}
function time(value){
  if(typeof value!=="string"||!OFFSET_TIMESTAMP.test(value)||!Number.isFinite(Date.parse(value)))throw new TypeError("occurredAt must be an ISO timestamp with an explicit UTC offset");
  return value;
}
function basis(input){
  if(!input||typeof input!=="object"||!/^[A-Z]{3}$/.test(input.currency||"")||!textValue(input.taxBasis)||!isIsoDate(input.periodStart)||!isIsoDate(input.periodEnd)||input.periodEnd<input.periodStart)throw new TypeError("A valid currency, tax basis and reporting period are required");
  return {currency:input.currency,taxBasis:input.taxBasis,periodStart:input.periodStart,periodEnd:input.periodEnd};
}
function textValue(value){return typeof value==="string"&&value.trim().length>0;}
function validateLedger(ledger){
  if(!ledger||typeof ledger!=="object"||Array.isArray(ledger)||!Array.isArray(ledger.events)||!textValue(ledger.id)||!textValue(ledger.tenantId)||!textValue(ledger.originRef))throw new TypeError("Value ledger is malformed");
  const ids=new Set();
  let previous=null;
  for(const event of ledger.events){
    if(!event||!VALUE_EVENT_TYPES.has(event.type)||ids.has(event.id)||!textValue(event.id))throw new TypeError("Value ledger event history is malformed");
    ids.add(event.id);
    if(previous&&Date.parse(event.occurredAt)<Date.parse(previous.occurredAt))throw new TypeError("Value ledger events must be chronological");
    previous=event;
  }
}

export function createValueLedger(input){
  if(!input||typeof input!=="object"||Array.isArray(input))throw new TypeError("Value ledger input is required");
  return {id:text(input.id,"ledger id"),tenantId:text(input.tenantId,"tenantId"),originRef:text(input.originRef,"originRef"),createdAt:time(input.createdAt),events:[]};
}

/**
 * Append a value-state event without overwriting earlier stages.
 * Amounts are positive magnitudes; credits and refunds remain distinct event
 * types and are never silently netted against invoiced or accepted value.
 * Provider settlement is deliberately outside this prototype's scope.
 */
export function appendValueEvent(ledger,input){
  validateLedger(ledger);
  if(!input||typeof input!=="object"||Array.isArray(input)||!VALUE_EVENT_TYPES.has(input.type))throw new TypeError("A supported value event type is required");
  const id=text(input.id,"event id");
  if(ledger.events.some(event=>event.id===id))throw new TypeError("Value event ID must be unique");
  const occurredAt=time(input.occurredAt);
  const last=ledger.events.at(-1);
  if(last&&Date.parse(occurredAt)<Date.parse(last.occurredAt))throw new TypeError("Value events must be chronological");
  const amount=cents(input.amount);
  if(amount===null||amount<=0n)throw new TypeError("Value amount must be a positive canonical decimal string");
  const reportingBasis=basis(input);
  const actorId=text(input.actorId,"actorId");
  const evidenceRef=text(input.evidenceRef,"evidenceRef",1000);
  const sourceRef=text(input.sourceRef,"sourceRef",1000);
  const reason=typeof input.reason==="string"?input.reason.trim():"";
  if(["contractually_accepted","variation_approved","delivered","customer_accepted","invoiced"].includes(input.type)&&!evidenceRef)throw new TypeError("This value state requires supporting evidence");
  if(["credited","refunded"].includes(input.type)&&(!reason||!textValue(input.invoiceRef)))throw new TypeError("Credits and refunds require a reason and invoice reference");
  if(input.type==="invoiced"&&!textValue(input.invoiceRef))throw new TypeError("Invoice events require an invoice reference");
  const sameValue=ledger.events.filter(event=>event.valueId===input.valueId);
  for(const event of sameValue){
    if(event.currency!==reportingBasis.currency||event.taxBasis!==reportingBasis.taxBasis)throw new TypeError("Value history cannot silently mix currencies or tax bases");
  }
  if(["credited","refunded"].includes(input.type)){
    const invoiced=sameValue.filter(event=>event.type==="invoiced"&&event.invoiceRef===input.invoiceRef).reduce((sum,event)=>sum+cents(event.amount),0n);
    const adjusted=sameValue.filter(event=>["credited","refunded"].includes(event.type)&&event.invoiceRef===input.invoiceRef).reduce((sum,event)=>sum+cents(event.amount),0n);
    if(invoiced===0n||adjusted+amount>invoiced)throw new TypeError("Credits and refunds cannot exceed evidenced invoiced value");
  }
  const event={
    id,type:input.type,valueId:text(input.valueId,"valueId"),amount:money(input.amount),
    ...reportingBasis,actorId,occurredAt,evidenceRef,sourceRef,
    invoiceRef:textValue(input.invoiceRef)?input.invoiceRef.trim():null,
    reason:reason||null,parentEventId:last?.id||null
  };
  return {...ledger,events:[...ledger.events,event]};
}

export function summarizeValueLedger(ledger){
  validateLedger(ledger);
  const totals=Object.fromEntries(TOTAL_TYPES.map(type=>[type,"0.00"]));
  const accumulators=Object.fromEntries(TOTAL_TYPES.map(type=>[type,0n]));
  for(const event of ledger.events)accumulators[event.type]+=cents(event.amount);
  for(const type of TOTAL_TYPES)totals[type]=decimal(accumulators[type]);
  const currencies=[...new Set(ledger.events.map(event=>event.currency))];
  const taxBases=[...new Set(ledger.events.map(event=>event.taxBasis))];
  return {
    ledgerId:ledger.id,tenantId:ledger.tenantId,eventCount:ledger.events.length,
    totalsByState:totals,
    currency:currencies.length===1?currencies[0]:null,
    taxBasis:taxBases.length===1?taxBases[0]:null,
    mixedReportingBasis:currencies.length>1||taxBases.length>1,
    settlementStatus:"not_in_scope",
    interpretation:"Stage totals are reported separately and must not be added together as realised value. Credits and refunds remain separate. No provider settlement, bank receipt, profit or recovered value is certified."
  };
}
