const PROMISE_TYPES=new Set(["customer_promise","internal_task"]);
const RESPONSIBLE_PARTIES=new Set(["business","customer","third_party"]);
const ACTOR_TYPES=new Set(["business_user","customer_contact","system"]);
const TERMINAL_STATUSES=new Set(["fulfilled","cancelled"]);
const TRANSITIONS={
  proposed:["communicated","accepted","cancelled"],
  communicated:["accepted","changed","disputed","cancelled"],
  accepted:["changed","fulfilled","missed","disputed","cancelled"],
  changed:["communicated","disputed","cancelled"],
  disputed:["accepted","changed","missed","cancelled"],
  missed:["fulfilled","disputed","cancelled"],
  fulfilled:[],
  cancelled:[]
};
const REVISION_FIELDS=new Set(["title","description","scope","exclusions","dueAt","dueTimezone","ownerId","responsibleParty"]);
const OFFSET_TIMESTAMP=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;

function requiredText(value,label,max=500){
  if(typeof value!=="string"||!value.trim()||value.trim().length>max)throw new TypeError(label+" is required and must be within its length limit");
  return value.trim();
}
function timestamp(value,label){
  if(typeof value!=="string"||!OFFSET_TIMESTAMP.test(value)||!Number.isFinite(Date.parse(value)))throw new TypeError(label+" must be an ISO timestamp with an explicit UTC offset");
  return value;
}
function timezone(value){
  const zone=requiredText(value,"dueTimezone",100);
  try{new Intl.DateTimeFormat("en-AU",{timeZone:zone}).format(new Date(0));}catch{throw new TypeError("dueTimezone must be a valid IANA timezone");}
  return zone;
}
function stringList(value,label,allowEmpty=false){
  if(!Array.isArray(value)||(!allowEmpty&&value.length===0)||value.some(x=>typeof x!=="string"||!x.trim()||x.trim().length>1000))throw new TypeError(label+" must be an array of non-empty strings");
  return value.map(x=>x.trim());
}
function versionSnapshot(input,version,metadata={}){
  if(!input||typeof input!=="object"||Array.isArray(input))throw new TypeError("Promise version details are required");
  if(!RESPONSIBLE_PARTIES.has(input.responsibleParty))throw new TypeError("responsibleParty is invalid");
  return {
    version,
    title:requiredText(input.title,"title",200),
    description:requiredText(input.description,"description",4000),
    scope:stringList(input.scope,"scope"),
    exclusions:stringList(input.exclusions,"exclusions",true),
    dueAt:timestamp(input.dueAt,"dueAt"),
    dueTimezone:timezone(input.dueTimezone),
    ownerId:requiredText(input.ownerId,"ownerId",255),
    responsibleParty:input.responsibleParty,
    changedAt:metadata.changedAt||null,
    changedBy:metadata.changedBy||null
  };
}
function validateRecord(record){
  if(!record||typeof record!=="object"||Array.isArray(record)||!PROMISE_TYPES.has(record.promiseType)||!Array.isArray(record.events)||!Array.isArray(record.versions)||!record.current||!Number.isInteger(record.currentVersion)||record.currentVersion<1||record.current.version!==record.currentVersion||record.versions.length!==record.currentVersion||!record.events.length||record.status!==record.events.at(-1).toStatus)
    throw new TypeError("Promise record is malformed");
}

export function createPromiseRecord(input){
  if(!input||typeof input!=="object"||Array.isArray(input))throw new TypeError("Promise input is required");
  if(!PROMISE_TYPES.has(input.promiseType))throw new TypeError("promiseType must be customer_promise or internal_task");
  const id=requiredText(input.id,"id",255);
  const tenantId=requiredText(input.tenantId,"tenantId",255);
  const createdBy=requiredText(input.createdBy,"createdBy",255);
  const createdAt=timestamp(input.createdAt,"createdAt");
  const eventId=requiredText(input.eventId,"eventId",255);
  const counterparty=input.promiseType==="customer_promise"?requiredText(input.counterparty,"counterparty",255):null;
  const current=versionSnapshot(input,1);
  const originRef=requiredText(input.originRef,"originRef",255);
  const event={id:eventId,type:"proposed",fromStatus:null,toStatus:"proposed",actorId:createdBy,actorType:"business_user",occurredAt:createdAt,reason:null,evidenceRef:null,messageRef:null,version:1};
  return {id,tenantId,promiseType:input.promiseType,counterparty,status:"proposed",currentVersion:1,current,versions:[current],originRef,events:[event],communicationMeaning:"A communicated event records that a message was sent; receipt and acceptance are separate and are never inferred."};
}

export function transitionPromise(record,event){
  validateRecord(record);
  if(!event||typeof event!=="object"||Array.isArray(event))throw new TypeError("Promise event is required");
  const id=requiredText(event.id,"event id",255);
  if(record.events.some(existing=>existing.id===id))throw new TypeError("Promise event ID must be unique");
  const type=requiredText(event.type,"event type",40);
  if(!Object.prototype.hasOwnProperty.call(TRANSITIONS,type))throw new TypeError("Promise event type is unsupported");
  const actorId=requiredText(event.actorId,"actorId",255);
  if(!ACTOR_TYPES.has(event.actorType))throw new TypeError("actorType is invalid");
  const occurredAt=timestamp(event.occurredAt,"occurredAt");
  const previousAt=Date.parse(record.events.at(-1).occurredAt);
  if(Date.parse(occurredAt)<previousAt)throw new TypeError("Promise events must be appended in chronological order");
  const fromStatus=record.status;
  if(TERMINAL_STATUSES.has(fromStatus)||!TRANSITIONS[fromStatus]?.includes(type))throw new TypeError("Promise status transition is not allowed");
  const reason=typeof event.reason==="string"?event.reason.trim():"";
  const evidenceRef=typeof event.evidenceRef==="string"?event.evidenceRef.trim():"";
  const messageRef=typeof event.messageRef==="string"?event.messageRef.trim():"";
  let nextVersion=record.current;
  let currentVersion=record.currentVersion;
  if(type==="communicated"){
    if(record.promiseType!=="customer_promise"||event.actorType!=="business_user"||!messageRef)throw new TypeError("Communication requires a business user and a message reference for a customer promise");
  }else if(type==="accepted"){
    const expectedActor=record.promiseType==="customer_promise"?"customer_contact":"business_user";
    if(event.actorType!==expectedActor||!evidenceRef)throw new TypeError("Acceptance requires the appropriate accepting party and acknowledgement evidence");
  }else if(type==="changed"){
    if(event.actorType!=="business_user"||!reason||!evidenceRef||!event.revision||typeof event.revision!=="object"||Array.isArray(event.revision))throw new TypeError("A change requires a business actor, reason, evidence reference and revised terms");
    if(Object.keys(event.revision).some(key=>!REVISION_FIELDS.has(key)))throw new TypeError("Promise revision contains unsupported fields");
    nextVersion=versionSnapshot({...record.current,...event.revision},record.currentVersion+1,{changedAt:occurredAt,changedBy:actorId});
    currentVersion=nextVersion.version;
  }else if(type==="fulfilled"){
    if(event.actorType!=="business_user"||!evidenceRef)throw new TypeError("Fulfilment requires a business actor and completion evidence");
  }else if(type==="missed"){
    if(!["business_user","system"].includes(event.actorType)||!reason||Date.parse(occurredAt)<Date.parse(record.current.dueAt))throw new TypeError("A missed commitment requires a reason and must be recorded no earlier than its due time");
  }else if(type==="disputed"){
    if(!["business_user","customer_contact"].includes(event.actorType)||!reason)throw new TypeError("A dispute requires an authorised party type and a reason");
  }else if(type==="cancelled"){
    if(!["business_user","customer_contact"].includes(event.actorType)||!reason)throw new TypeError("Cancellation requires an authorised party type and a reason");
  }
  const toStatus=type;
  const appended={id,type,fromStatus,toStatus,actorId,actorType:event.actorType,occurredAt,reason:reason||null,evidenceRef:evidenceRef||null,messageRef:messageRef||null,version:currentVersion};
  return {
    ...record,
    status:toStatus,
    currentVersion,
    current:nextVersion,
    versions:nextVersion===record.current?record.versions:[...record.versions,nextVersion],
    events:[...record.events,appended]
  };
}
