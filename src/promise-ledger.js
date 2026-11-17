import {isIsoDate} from "./engine.js";
const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const TRANSITIONS={
  proposed:new Set(["communicated","cancelled"]),
  communicated:new Set(["accepted","disputed","cancelled"]),
  accepted:new Set(["changed","fulfilled","missed","disputed","cancelled"]),
  changed:new Set(["accepted","fulfilled","missed","disputed","cancelled"]),
  missed:new Set(["fulfilled","disputed"]),
  disputed:new Set(["accepted","changed","fulfilled","cancelled"]),
  fulfilled:new Set(),
  cancelled:new Set()
};
const EVIDENCE_REQUIRED=new Set(["communicated","accepted","changed","fulfilled","missed","disputed"]);
const HAS_TIMEZONE=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;
const clean=(value,max)=>typeof value==="string"?value.trim().slice(0,max):"";
const validTime=value=>typeof value==="string"&&HAS_TIMEZONE.test(value)&&isIsoDate(value.slice(0,10))&&Number.isFinite(Date.parse(value));

function validateHistory(events,promiseId){
  const seen=new Set();
  let previousState=null,previousTime=null;
  for(const item of events){
    if(!item||typeof item!=="object"||Array.isArray(item)||
       item.promiseId!==promiseId||!ID.test(item.eventId||"")||seen.has(item.eventId)||
       !ID.test(item.actorId||"")||!ID.test(item.sourceRef||"")||
       !TRANSITIONS[item.type]||!validTime(item.occurredAt)||
       typeof item.reason!=="string"||item.reason.trim().length<3||
       !Array.isArray(item.evidenceRefs)||!item.evidenceRefs.some(x=>typeof x==="string"&&ID.test(x.trim()))){
      throw new TypeError("Existing promise history contains an invalid event.");
    }
    if(!previousState&&item.type!=="proposed")throw new TypeError("Existing promise history must begin with a proposed event.");
    if(previousState&&!TRANSITIONS[previousState].has(item.type))throw new Error("Existing promise history contains an invalid state transition.");
    if(previousTime!==null&&Date.parse(item.occurredAt)<previousTime)throw new Error("Existing promise history is not chronological.");
    if(EVIDENCE_REQUIRED.has(item.type)&&item.evidenceRefs.length===0)throw new TypeError("Existing material promise events require evidence.");
    seen.add(item.eventId);
    previousState=item.type;
    previousTime=Date.parse(item.occurredAt);
  }
  return {seen,previousState,previousTime};
}

/**
 * Append one immutable promise event. Persistence, actor authentication and
 * source-reference authorisation must be enforced by the server/database.
 */
export function appendPromiseEvent({events=[],event}={}){
  if(!Array.isArray(events)||events.length>10000)throw new TypeError("Promise events must be an array of at most 10,000 entries.");
  if(!event||typeof event!=="object"||Array.isArray(event))throw new TypeError("A promise event object is required.");
  const promiseId=clean(event.promiseId,128),eventId=clean(event.eventId,128),actorId=clean(event.actorId,128);
  const nextState=clean(event.type,32),sourceRef=clean(event.sourceRef,128),reason=clean(event.reason,1000);
  if(!ID.test(promiseId)||!ID.test(eventId)||!ID.test(actorId)||!ID.test(sourceRef))
    throw new TypeError("Promise, event, actor and source identifiers must be safe non-empty IDs.");
  if(!reason||reason.length<3)throw new TypeError("A reason of at least three characters is required.");
  if(!validTime(event.occurredAt))throw new TypeError("occurredAt must be a valid ISO timestamp with an explicit timezone.");
  const evidenceRefs=Array.isArray(event.evidenceRefs)
    ?event.evidenceRefs.filter(x=>typeof x==="string"&&ID.test(x.trim())).map(x=>x.trim()).slice(0,50):[];
  if(EVIDENCE_REQUIRED.has(nextState)&&evidenceRefs.length===0)
    throw new Error("This promise transition requires at least one evidence reference.");
  if(!TRANSITIONS[nextState])throw new Error("Unsupported promise event type.");
  const history=validateHistory(events,promiseId);
  if(history.seen.has(eventId))throw new Error("Duplicate promise event ID.");
  if(!history.previousState&&nextState!=="proposed")throw new Error("A promise must begin with a proposed event.");
  if(history.previousState&&!TRANSITIONS[history.previousState].has(nextState))
    throw new Error("Invalid promise state transition from "+history.previousState+" to "+nextState+".");
  if(history.previousTime!==null&&Date.parse(event.occurredAt)<history.previousTime)
    throw new Error("Promise events must be appended in chronological order.");
  const appended={promiseId,eventId,type:nextState,actorId,occurredAt:event.occurredAt,sourceRef,reason,evidenceRefs};
  const nextEvents=events.map(x=>({...x,evidenceRefs:[...x.evidenceRefs]}));
  nextEvents.push(appended);
  return {promiseId,state:nextState,events:nextEvents,latestEvent:{...appended,evidenceRefs:[...evidenceRefs]},terminal:["fulfilled","cancelled"].includes(nextState)};
}
