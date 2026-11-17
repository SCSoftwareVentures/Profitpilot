const KNOWLEDGE_TYPES=new Set(["verified_instruction","customer_preference","observation","suggestion","unverified_note"]);
const VISIBILITIES=new Set(["private","site","team"]);
const REVIEW_OUTCOMES=new Set(["confirmed","corrected","rejected","needs_review"]);
const OFFSET_TIMESTAMP=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;
function text(value,label,max=500){if(typeof value!=="string"||!value.trim()||value.trim().length>max)throw new TypeError(label+" is required and must be within its length limit");return value.trim();}
function time(value,label){if(typeof value!=="string"||!OFFSET_TIMESTAMP.test(value)||!Number.isFinite(Date.parse(value)))throw new TypeError(label+" must be an ISO timestamp with an explicit UTC offset");return value;}
function list(value,label){if(!Array.isArray(value)||value.length>100||value.some(x=>typeof x!=="string"||!x.trim()||x.trim().length>255))throw new TypeError(label+" must be an array of non-empty identifiers");return [...new Set(value.map(x=>x.trim()))].sort();}
function validateItem(item){if(!item||typeof item!=="object"||Array.isArray(item)||!Array.isArray(item.events)||!Array.isArray(item.versions)||!item.current||!Number.isInteger(item.currentVersion)||item.currentVersion<1||item.current.version!==item.currentVersion||item.versions.length!==item.currentVersion||!item.events.length)throw new TypeError("Knowledge record is malformed");}
function snapshot(input,version){
 if(!KNOWLEDGE_TYPES.has(input.knowledgeType))throw new TypeError("knowledgeType is invalid");
 if(!VISIBILITIES.has(input.visibility))throw new TypeError("visibility is invalid");
 if(!Number.isInteger(input.confidence)||input.confidence<0||input.confidence>100)throw new TypeError("confidence must be an integer from 0 to 100");
 const reviewAt=time(input.reviewAt,"reviewAt"),expiresAt=input.expiresAt==null?null:time(input.expiresAt,"expiresAt");
 if(expiresAt&&Date.parse(expiresAt)<=Date.parse(input.recordedAt))throw new TypeError("expiresAt must be later than recordedAt");
 const evidenceRef=input.evidenceRef==null?null:text(input.evidenceRef,"evidenceRef",255),reviewerId=input.reviewerId==null?null:text(input.reviewerId,"reviewerId",255);
 if(input.knowledgeType==="verified_instruction"&&(!evidenceRef||!reviewerId))throw new TypeError("verified_instruction requires evidenceRef and reviewerId");
 if(input.knowledgeType==="customer_preference"&&!evidenceRef)throw new TypeError("customer_preference requires evidenceRef");
 return {version,knowledgeType:input.knowledgeType,title:text(input.title,"title",200),content:text(input.content,"content",4000),siteId:input.siteId==null?null:text(input.siteId,"siteId",255),visibility:input.visibility,teamIds:list(input.teamIds??[],"teamIds"),sourceRef:text(input.sourceRef,"sourceRef",255),evidenceRef,confidence:input.confidence,ownerId:text(input.ownerId,"ownerId",255),reviewerId,recordedAt:time(input.recordedAt,"recordedAt"),reviewAt,expiresAt,reviewOutcome:input.reviewOutcome??"needs_review"};
}
/** Create a versioned in-memory knowledge record; no persistence is performed. */
export function createKnowledgeItem(input){
 if(!input||typeof input!=="object"||Array.isArray(input))throw new TypeError("Knowledge input is required");
 const id=text(input.id,"id",255),tenantId=text(input.tenantId,"tenantId",255),current=snapshot(input,1);
 if(current.visibility==="site"&&!current.siteId)throw new TypeError("site visibility requires siteId");
 if(current.visibility==="team"&&!current.teamIds.length)throw new TypeError("team visibility requires at least one teamId");
 if(current.knowledgeType==="verified_instruction"&&current.reviewOutcome!=="confirmed")throw new TypeError("verified_instruction must have a confirmed review outcome");
 const event={id:text(input.eventId,"eventId",255),type:"created",actorId:current.ownerId,occurredAt:current.recordedAt,itemVersion:1,reason:null};
 return {id,tenantId,status:"active",currentVersion:1,current,versions:[current],events:[event]};
}
/** Append a review/version; previous knowledge is retained rather than overwritten. */
export function reviewKnowledgeItem(item,review){
 validateItem(item);if(!review||typeof review!=="object"||Array.isArray(review))throw new TypeError("A review event is required");
 const eventId=text(review.eventId,"eventId",255);if(item.events.some(e=>e.id===eventId))throw new TypeError("Knowledge event ID must be unique");
 const actorId=text(review.actorId,"actorId",255),occurredAt=time(review.occurredAt,"occurredAt");
 if(Date.parse(occurredAt)<Date.parse(item.events.at(-1).occurredAt))throw new TypeError("Knowledge events must be chronological");
 if(!REVIEW_OUTCOMES.has(review.outcome))throw new TypeError("Review outcome is invalid");
 const reason=text(review.reason,"reason",1000);
 if(review.outcome==="rejected"||review.outcome==="needs_review"){
  const event={id:eventId,type:review.outcome,actorId,occurredAt,itemVersion:item.currentVersion,reason};
  return {...item,status:review.outcome==="rejected"?"rejected":"review_required",events:[...item.events,event]};
 }
 if(!review.revision||typeof review.revision!=="object"||Array.isArray(review.revision))throw new TypeError("A review revision is required");
 const allowed=new Set(["knowledgeType","title","content","siteId","visibility","teamIds","sourceRef","evidenceRef","confidence","reviewAt","expiresAt","reviewerId"]);
 if(Object.keys(review.revision).some(k=>!allowed.has(k)))throw new TypeError("Knowledge revision contains unsupported fields");
 const nextInput={...item.current,...review.revision,recordedAt:occurredAt,reviewerId:actorId,reviewOutcome:"confirmed"};
 if(review.evidenceRef)nextInput.evidenceRef=review.evidenceRef;
 const next=snapshot(nextInput,item.currentVersion+1);
 if(next.visibility==="site"&&!next.siteId)throw new TypeError("site visibility requires siteId");
 if(next.visibility==="team"&&!next.teamIds.length)throw new TypeError("team visibility requires at least one teamId");
 if(next.knowledgeType==="verified_instruction"&&!next.evidenceRef)throw new TypeError("verified_instruction requires review evidence");
 const event={id:eventId,type:review.outcome,actorId,occurredAt,itemVersion:next.version,reason,evidenceRef:review.evidenceRef??next.evidenceRef};
 return {...item,status:"active",currentVersion:next.version,current:next,versions:[...item.versions,next],events:[...item.events,event]};
}
/** Permission-filtered retrieval. Missing access context returns no records. */
export function searchKnowledge(items,query,access,now){
 if(!Array.isArray(items))throw new TypeError("Knowledge items must be an array");
 if(!access||typeof access!=="object"||Array.isArray(access)||typeof access.tenantId!=="string"||typeof access.actorId!=="string"||!Array.isArray(access.siteIds)||!Array.isArray(access.teamIds))return [];
 const instant=time(now,"now"),needle=typeof query==="string"?query.trim().toLocaleLowerCase("en"):"";
 return items.filter(item=>{
  try{validateItem(item);}catch{return false;}
  if(item.tenantId!==access.tenantId||item.status!=="active")return false;
  const k=item.current;
  if(k.reviewOutcome!=="confirmed"||Date.parse(k.reviewAt)<=Date.parse(instant)||(k.expiresAt&&Date.parse(k.expiresAt)<=Date.parse(instant)))return false;
  const allowed=k.visibility==="private"?k.ownerId===access.actorId:k.visibility==="site"?access.siteIds.includes(k.siteId):k.visibility==="team"?k.teamIds.some(id=>access.teamIds.includes(id)):false;
  return allowed&&(!needle||(k.title+" "+k.content+" "+(k.siteId??"")).toLocaleLowerCase("en").includes(needle));
 }).map(item=>({id:item.id,version:item.currentVersion,...item.current,reviewStatus:"current_reviewed",interpretation:"Stored operational knowledge, not an automatic instruction or safety/compliance approval."}));
}
