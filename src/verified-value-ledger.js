import {money,isIsoDate} from "./engine.js";

const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TYPES=["proposed","quoted","contracted","variation_approved","delivered","customer_accepted","invoiced","credited","refunded","settled","disputed"];
const TAX_BASES=new Set(["gst_inclusive","gst_exclusive","no_gst","unknown"]);
const TIME=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;
const clean=(value,max)=>typeof value==="string"?value.trim().slice(0,max):"";
const cents=value=>{
  const canonical=money(value);
  if(canonical===null)return null;
  const negative=canonical.startsWith("-");
  const unsigned=negative?canonical.slice(1):canonical;
  const [whole,fraction]=unsigned.split(".");
  const n=BigInt(whole)*100n+BigInt(fraction);
  return negative?-n:n;
};
const format=value=>{
  const negative=value<0n,absolute=negative?-value:value;
  return (negative?"-":"")+String(absolute/100n)+"."+String(absolute%100n).padStart(2,"0");
};
function validateEvent(event,expectedValueId){
  if(!event||typeof event!=="object"||Array.isArray(event))throw new TypeError("Value event history contains an invalid event.");
  const valueId=clean(event.valueId,128),eventId=clean(event.eventId,128),actorId=clean(event.actorId,128);
  const scopeRef=clean(event.scopeRef,128),sourceRef=clean(event.sourceRef,128);
  const amount=cents(event.amount),currency=clean(event.currency,3),taxBasis=clean(event.taxBasis,32);
  if(!ID.test(valueId)||!ID.test(eventId)||!ID.test(actorId)||!ID.test(scopeRef)||!ID.test(sourceRef)||
     (expectedValueId&&valueId!==expectedValueId)||!TYPES.includes(event.type)||
     amount===null||amount<=0n||!/^[A-Z]{3}$/.test(currency)||!TAX_BASES.has(taxBasis)||
     !isIsoDate(event.periodStart)||!isIsoDate(event.periodEnd)||event.periodEnd<event.periodStart||
     typeof event.occurredAt!=="string"||!TIME.test(event.occurredAt)||!Number.isFinite(Date.parse(event.occurredAt))||
     typeof event.reason!=="string"||event.reason.trim().length<3||
     !Array.isArray(event.evidenceRefs)||!event.evidenceRefs.some(x=>typeof x==="string"&&ID.test(x.trim()))){
    throw new TypeError("Value event identity, amount, dimensions, timestamp, reason or evidence is invalid.");
  }
  return {valueId,eventId,scopeRef,amount,currency,taxBasis,periodStart:event.periodStart,periodEnd:event.periodEnd,occurredAt:event.occurredAt};
}
function dimensionKey(event){return [event.scopeRef,event.currency,event.taxBasis,event.periodStart,event.periodEnd].join("|");}

/**
 * Append a separately classified value event. No stages are netted together:
 * credits, refunds and settlements remain visible as independent evidence states.
 */
export function appendValueEvent({events=[],event}={}){
  if(!Array.isArray(events)||events.length>20000)throw new TypeError("Value events must be an array of at most 20,000 entries.");
  const next=validateEvent(event);
  const seen=new Set();
  let previousTime=null,expectedDimensions=null;
  for(const old of events){
    const checked=validateEvent(old,next.valueId);
    if(seen.has(checked.eventId))throw new TypeError("Existing value history contains duplicate event IDs.");
    seen.add(checked.eventId);
    const dimensions=dimensionKey(checked);
    if(expectedDimensions!==null&&dimensions!==expectedDimensions)throw new TypeError("Existing value history mixes scope, currency, tax basis or reporting period.");
    expectedDimensions=dimensions;
    if(previousTime!==null&&Date.parse(checked.occurredAt)<previousTime)throw new TypeError("Existing value history is not chronological.");
    previousTime=Date.parse(checked.occurredAt);
  }
  if(seen.has(next.eventId))throw new Error("Duplicate value event ID.");
  if(expectedDimensions!==null&&dimensionKey(next)!==expectedDimensions)
    throw new Error("A value record cannot change scope, currency, tax basis or reporting period.");
  if(previousTime!==null&&Date.parse(next.occurredAt)<previousTime)
    throw new Error("Value events must be appended in chronological order.");
  const evidenceRefs=event.evidenceRefs.filter(x=>typeof x==="string"&&ID.test(x.trim())).map(x=>x.trim()).slice(0,50);
  const appended={...event,valueId:next.valueId,eventId:next.eventId,actorId:clean(event.actorId,128),scopeRef:next.scopeRef,type:event.type,amount:format(next.amount),currency:next.currency,taxBasis:next.taxBasis,periodStart:next.periodStart,periodEnd:next.periodEnd,sourceRef:clean(event.sourceRef,128),evidenceRefs};
  const nextEvents=events.map(x=>({...x,evidenceRefs:[...x.evidenceRefs]}));
  nextEvents.push(appended);
  return {valueId:next.valueId,events:nextEvents,latestEvent:{...appended,evidenceRefs:[...evidenceRefs]}};
}

export function summariseValueEvents(events=[]){
  if(!Array.isArray(events)||events.length>20000)throw new TypeError("Value events must be an array of at most 20,000 entries.");
  const groups=new Map(),perValue=new Map(),eventIds=new Map();
  for(const event of events){
    const checked=validateEvent(event);
    const seen=eventIds.get(checked.valueId)||new Set();
    if(seen.has(checked.eventId))throw new TypeError("Value event history contains duplicate event IDs.");
    seen.add(checked.eventId);eventIds.set(checked.valueId,seen);
    const state=perValue.get(checked.valueId)||{dimensions:dimensionKey(checked),lastTime:null};
    if(state.dimensions!==dimensionKey(checked))throw new TypeError("A value record contains mixed reporting dimensions.");
    if(state.lastTime!==null&&Date.parse(checked.occurredAt)<state.lastTime)
      throw new TypeError("Value event history is not chronological.");
    state.lastTime=Date.parse(checked.occurredAt);perValue.set(checked.valueId,state);
    const key=dimensionKey(checked);
    if(!groups.has(key)){
      groups.set(key,{
        scopeRef:checked.scopeRef,currency:checked.currency,taxBasis:checked.taxBasis,
        period:{start:checked.periodStart,end:checked.periodEnd},
        totals:Object.fromEntries(TYPES.map(type=>[type,0n])),
        counts:Object.fromEntries(TYPES.map(type=>[type,0])),
        eventCount:0
      });
    }
    const group=groups.get(key);
    group.totals[event.type]+=checked.amount;
    group.counts[event.type]++;
    group.eventCount++;
  }
  return [...groups.values()].map(group=>({
    scopeRef:group.scopeRef,currency:group.currency,taxBasis:group.taxBasis,period:group.period,eventCount:group.eventCount,
    recordedAmounts:Object.fromEntries(TYPES.map(type=>[type,group.counts[type]?format(group.totals[type]):null])),
    eventTypeCounts:{...group.counts},
    creditedAndRefunded:(group.counts.credited+group.counts.refunded)?format(group.totals.credited+group.totals.refunded):null,
    nettedTotal:null,
    verificationStatus:"not_independently_verified",
    limitations:[
      "Quoted, contracted, approved, delivered, accepted, invoiced, credited, refunded and settled values are separate states, not interchangeable measures.",
      "Credits and refunds are reported separately and are not silently netted against invoice or settlement totals.",
      "Recorded events and evidence references are not independently verified by this in-memory domain function."
    ]
  }));
}
