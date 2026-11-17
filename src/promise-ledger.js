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
const HAS_TIMEZONE=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;
const clean=(value,max)=>typeof value==="string"?value.trim().slice(0,max):"";

/**
 * Append one immutable promise event. This is an in-memory domain primitive;
 * persistence, actor authentication and source-reference authorisation are external.
 */
export function appendPromiseEvent({events=[],event}={}){
  if(!Array.isArray(events)||events.length>10000)throw new TypeError("Promise events must be an array of at most 10,000 entries.");
  if(!event||typeof event!=="object"||Array.isArray(event))throw new TypeError("A promise event object is required.");
  const promiseId=clean(event.promiseId,128),eventId=clean(event.eventId,128),actorId=clean(event.actorId,128);
  const nextState=clean(event.type,32),sourceRef=clean(event.sourceRef,128),reason=clean(event.reason,1000);
  if(!ID.test(promiseId)||!ID.test(eventId)||!ID.test(actorId)||!ID.test(sourceRef))throw new TypeError("Promise, event, actor and source identifiers must be safe non-empty IDs.");
  if(!reason||reason.length<3)throw new TypeError("A reason of at least three characters is required.");
  if(!HAS_TIMEZONE.test(event.occurredAt||"")||!Number.isFinite(Date.parse(event.occurredAt)))throw new TypeError("occurredAt must be a valid ISO timestamp with an explicit timezone.");
  if(events.some(x=>!x||x.promiseId!==promiseId||!ID.test(x.eventId||"")))throw new TypeError("Existing events must be valid and belong to the same promise.");
  if(events.some(x=>x.eventId===eventId))throw new Error("Duplicate promise event ID.");
  const previous=events.at(-1)||null;
  const currentState=previous?.type||null;
  if(!currentState&&nextState!=="proposed")throw new Error("A promise must begin with a proposed event.");
  if(currentState&&!TRANSITIONS[currentState]?.has(nextState))throw new Error("Invalid promise state transition from "+currentState+" to "+nextState+".");
  if(previous&&Date.parse(event.occurredAt)<Date.parse(previous.occurredAt))throw new Error("Promise events must be appended in chronological order.");
  const evidenceRefs=Array.isArray(event.evidenceRefs)?event.evidenceRefs.filter(x=>typeof x==="string"&&ID.test(x.trim())).map(x=>x.trim()).slice(0,50):[];
  if(["communicated","accepted","changed","fulfilled","missed","disputed"].includes(nextState)&&evidenceRefs.length===0)throw new Error("This promise transition requires at least one evidence reference.");
  const appended={promiseId,eventId,type:nextState,actorId,occurredAt:event.occurredAt,sourceRef,reason,evidenceRefs};
  const nextEvents=events.map(x=>({...x,evidenceRefs:[...(x.evidenceRefs||[])]}));
  nextEvents.push(appended);
  return {promiseId,state:nextState,events:nextEvents,latestEvent:{...appended,evidenceRefs:[...evidenceRefs]},terminal:["fulfilled","cancelled"].includes(nextState)};
}
