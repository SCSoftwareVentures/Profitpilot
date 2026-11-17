import {money,isIsoDate} from "./engine.js";

const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TYPES=["proposed","quoted","contracted","variation_approved","delivered","customer_accepted","invoiced","credited","refunded","settled","disputed"];
const TAX_BASES=new Set(["gst_inclusive","gst_exclusive","no_gst","unknown"]);
const clean=(value,max)=>typeof value==="string"?value.trim().slice(0,max):"";
const cents=value=>{const canonical=money(value);if(canonical===null)return null;const negative=canonical.startsWith("-");const unsigned=negative?canonical.slice(1):canonical;const [whole,fraction]=unsigned.split(".");const n=BigInt(whole)*100n+BigInt(fraction);return negative?-n:n;};
const format=value=>{const negative=value<0n,absolute=negative?-value:value;return (negative?"-":"")+String(absolute/100n)+"."+String(absolute%100n).padStart(2,"0");};

/**
 * Append a separately classified value event. No stages are netted together:
 * credits, refunds and settlements remain visible as independent evidence states.
 */
export function appendValueEvent({events=[],event}={}){
  if(!Array.isArray(events)||events.length>20000)throw new TypeError("Value events must be an array of at most 20,000 entries.");
  if(!event||typeof event!=="object"||Array.isArray(event))throw new TypeError("A value event object is required.");
  const valueId=clean(event.valueId,128),eventId=clean(event.eventId,128),actorId=clean(event.actorId,128),scopeRef=clean(event.scopeRef,128);
  const type=clean(event.type,40),sourceRef=clean(event.sourceRef,128),currency=clean(event.currency,3),taxBasis=clean(event.taxBasis,32);
  const amount=cents(event.amount),periodStart=event.periodStart,periodEnd=event.periodEnd;
  const reason=clean(event.reason,1000);
  const evidenceRefs=Array.isArray(event.evidenceRefs)?event.evidenceRefs.filter(x=>typeof x==="string"&&ID.test(x.trim())).map(x=>x.trim()).slice(0,50):[];
  if(!ID.test(valueId)||!ID.test(eventId)||!ID.test(actorId)||!ID.test(scopeRef)||!ID.test(sourceRef))throw new TypeError("Value, event, actor and source identifiers must be safe non-empty IDs.");
  if(!TYPES.includes(type))throw new TypeError("Unsupported value event type.");
  if(amount===null||amount<=0n)throw new TypeError("Value event amount must be a positive canonical decimal string.");
  if(!/^[A-Z]{3}$/.test(currency)||!TAX_BASES.has(taxBasis))throw new TypeError("Value event currency and tax basis must be explicit.");
  if(!isIsoDate(periodStart)||!isIsoDate(periodEnd)||periodEnd<periodStart)throw new TypeError("Value event reporting period must be valid ISO dates.");
  if(!reason||reason.length<3||evidenceRefs.length===0)throw new TypeError("A reason and at least one evidence reference are required.");
  if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/.test(event.occurredAt||"")||!Number.isFinite(Date.parse(event.occurredAt)))throw new TypeError("occurredAt must be a valid ISO timestamp with an explicit timezone.");
  if(events.some(x=>!x||x.valueId!==valueId||!ID.test(x.eventId||"")))throw new TypeError("Existing value events must belong to the same value record.");
  if(events.some(x=>x.eventId===eventId))throw new Error("Duplicate value event ID.");
  const previous=events.at(-1);
  if(previous&&Date.parse(event.occurredAt)<Date.parse(previous.occurredAt))throw new Error("Value events must be appended in chronological order.");
  const appended={valueId,eventId,actorId,scopeRef,type,amount:format(amount),currency,taxBasis,periodStart,periodEnd,sourceRef,occurredAt:event.occurredAt,reason,evidenceRefs};
  const nextEvents=events.map(x=>({...x,evidenceRefs:[...(x.evidenceRefs||[])]}));
  nextEvents.push(appended);
  return {valueId,events:nextEvents,latestEvent:{...appended,evidenceRefs:[...evidenceRefs]}};
}

export function summariseValueEvents(events=[]){
  if(!Array.isArray(events)||events.length>20000)throw new TypeError("Value events must be an array of at most 20,000 entries.");
  const groups=new Map();
  for(const event of events){
    if(!event||typeof event!=="object"||!ID.test(event.valueId||"")||!TYPES.includes(event.type))throw new TypeError("Value event history contains an invalid event.");
    const scopeRef=clean(event.scopeRef,128);\n    if(!ID.test(scopeRef))throw new TypeError("Value event scope reference is missing or invalid.");\n    const key=[scopeRef,event.currency,event.taxBasis,event.periodStart,event.periodEnd].join("|");
    if(!/^[A-Z]{3}$/.test(event.currency||"")||!TAX_BASES.has(event.taxBasis)||!isIsoDate(event.periodStart)||!isIsoDate(event.periodEnd)||event.periodEnd<event.periodStart)throw new TypeError("Value event dimensions are missing or invalid.");
    const amount=cents(event.amount);if(amount===null||amount<=0n)throw new TypeError("Value event amount is invalid.");
    if(!groups.has(key))groups.set(key,{currency:event.currency,taxBasis:event.taxBasis,period:{start:event.periodStart,end:event.periodEnd},totals:Object.fromEntries(TYPES.map(type=>[type,0n])),eventCount:0});
    const group=groups.get(key);group.totals[event.type]+=amount;group.eventCount++;
  }
  return [...groups.values()].map(group=>({
    currency:group.currency,
    taxBasis:group.taxBasis,
    period:group.period,
    eventCount:group.eventCount,
    recordedAmounts:Object.fromEntries(TYPES.map(type=>[type,format(group.totals[type])])),
    creditedAndRefunded:format(group.totals.credited+group.totals.refunded),
    nettedTotal:null,
    verificationStatus:"not_independently_verified",
    limitations:[
      "Quoted, contracted, approved, delivered, accepted, invoiced, credited, refunded and settled values are separate states, not interchangeable measures.",
      "Credits and refunds are reported separately and are not silently netted against invoice or settlement totals.",
      "Recorded events and evidence references are not independently verified by this in-memory domain function."
    ]
  }));
}
