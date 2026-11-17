const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const VISIBILITY=new Set(["internal","customer_visible","restricted"]);
const CONFIDENCE=new Set(["verified","reported","inferred","unverified"]);
const clean=(value,max)=>typeof value==="string"?value.trim().slice(0,max):"";
function validDate(value){if(typeof value!=="string"||!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value))return false;const d=new Date(value+"T00:00:00.000Z");return Number.isFinite(d.getTime())&&d.toISOString().slice(0,10)===value;}

/** Create a permission-scoped knowledge record; persistence and identity are external. */
export function createKnowledgeEntry(input={}){
  if(!input||typeof input!=="object"||Array.isArray(input))throw new TypeError("A knowledge entry object is required.");
  const id=clean(input.id,128),tenantId=clean(input.tenantId,128),scopeRef=clean(input.scopeRef,128),ownerId=clean(input.ownerId,128),sourceRef=clean(input.sourceRef,128),type=clean(input.type,64);
  const visibility=clean(input.visibility,32),confidence=clean(input.confidence,32),content=clean(input.content,2000);
  const customerId=clean(input.customerId,128);
  const evidenceRefs=Array.isArray(input.evidenceRefs)?input.evidenceRefs.filter(x=>typeof x==="string"&&ID.test(x.trim())).map(x=>x.trim()).slice(0,50):[];
  if(![id,tenantId,scopeRef,ownerId,sourceRef,type].every(x=>ID.test(x)))throw new TypeError("Knowledge entry, tenant, scope, owner, source and type identifiers are required.");
  if(!VISIBILITY.has(visibility)||!CONFIDENCE.has(confidence))throw new TypeError("Knowledge visibility and confidence must be explicit.");
  if(!content||!validDate(input.reviewAt)||!validDate(input.expiresAt)||!validDate(input.asOf)||input.expiresAt<input.reviewAt)throw new TypeError("Knowledge content and valid review/expiry dates are required.");
  if(confidence==="verified"&&evidenceRefs.length===0)throw new TypeError("Verified knowledge requires at least one evidence reference.");
  if(visibility==="customer_visible"&&!ID.test(customerId))throw new TypeError("Customer-visible knowledge requires a customer scope.");
  if(visibility!=="customer_visible"&&customerId)throw new TypeError("Customer scope is only valid for customer-visible knowledge.");
  const state=input.expiresAt<input.asOf?"expired":input.reviewAt<=input.asOf?"review_due":"current";
  return {id,tenantId,scopeRef,ownerId,sourceRef,type,visibility,confidence,content,evidenceRefs,customerId:customerId||null,reviewAt:input.reviewAt,expiresAt:input.expiresAt,state,requiresReview:state!=="current",verificationStatus:"caller_asserted_not_independently_verified",asOf:input.asOf};
}

/** Tenant and visibility gate for an already-authenticated actor. */
export function canReadKnowledgeEntry(entry,actor){
  if(!entry||!actor||typeof actor!=="object"||Array.isArray(actor)||actor.tenantId!==entry.tenantId)return false;
  if(entry.visibility==="internal")return true;
  if(entry.visibility==="customer_visible")return typeof actor.customerId==="string"&&actor.customerId===entry.customerId;
  if(entry.visibility==="restricted")return actor.userId===entry.ownerId||Array.isArray(actor.roles)&&actor.roles.some(role=>["owner","admin"].includes(role));
  return false;
}
