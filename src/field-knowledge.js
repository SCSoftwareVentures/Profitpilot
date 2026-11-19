// Field Knowledge Memory: versioned, permission-aware knowledge records.
// In-memory domain logic only; no network, filesystem or persistence.
const ROLES = new Set(["owner","admin","manager","site_staff","analyst","reviewer"]);
const TYPES = new Set(["site_requirement","scope_clarification","equipment_constraint","recurring_issue","resolution","safety_reference","customer_preference"]);
const VISIBILITY = new Set(["tenant","site_team","owner_admin"]);
const CONFIDENCE = new Set(["verified","unverified","needs_review"]);
const STATUSES = new Set(["active","disputed","superseded"]);
const KEY = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const DATETIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})$/;
const SECRET = /\b(password|passcode|pin\s*code|alarm\s*code|api\s*key|secret\s*key|bank\s*account|tax\s*file\s*number)\b/i;

function validDate(value) {
  if (typeof value !== "string" || !DATE.test(value)) return false;
  const d = new Date(value + "T00:00:00.000Z");
  return Number.isFinite(d.getTime()) && d.toISOString().slice(0,10) === value;
}
function validDateTime(value) {
  return typeof value === "string" && DATETIME.test(value) && validDate(value.slice(0,10)) && Number.isFinite(Date.parse(value));
}
function requireText(value, label, max=500) {
  if (typeof value !== "string" || !value.trim() || value.trim().length > max) throw new TypeError(label + " is required and must be no longer than " + max + " characters.");
  return value.trim();
}
function validateActor(actor, tenantId) {
  if (!actor || typeof actor !== "object" || actor.tenantId !== tenantId ||
      !ID.test(actor.id || "") || !ROLES.has(actor.role)) throw new TypeError("A valid actor with active tenant context is required.");
  if (actor.siteIds !== undefined && (!Array.isArray(actor.siteIds) || actor.siteIds.some(id => typeof id !== "string"))) throw new TypeError("Actor siteIds must be an array of site identifiers.");
}
function validateScope(scope) {
  if (!scope || !["site","customer","contract"].includes(scope.type) || !ID.test(scope.id || "")) throw new TypeError("Scope must identify a site, customer or contract.");
}
function validateDates({sourceDate,reviewBy,expiresOn}) {
  if (!validDate(sourceDate) || !validDate(reviewBy) || (expiresOn !== null && expiresOn !== undefined && !validDate(expiresOn))) throw new TypeError("Source, review and expiry dates must be real ISO calendar dates.");
  if (reviewBy < sourceDate || (expiresOn && expiresOn < sourceDate)) throw new RangeError("Review and expiry dates cannot precede the source date.");
}
function validateContent(title, content) {
  const combined = title + "\n" + content;
  if (SECRET.test(combined)) throw new TypeError("Authentication secrets, access codes and financial identifiers must not be stored in Field Knowledge Memory.");
}

export function createKnowledgeRecord(input={}) {
  const tenantId = requireText(input.tenantId,"Tenant ID",128);
  validateActor(input.actor,tenantId);
  validateScope(input.scope);
  if (!TYPES.has(input.knowledgeType)) throw new TypeError("Unsupported knowledge type.");
  if (!KEY.test(input.key || "")) throw new TypeError("Knowledge key must be a stable lowercase slug.");
  if (!VISIBILITY.has(input.visibility)) throw new TypeError("Unsupported visibility.");
  if (!CONFIDENCE.has(input.confidence)) throw new TypeError("Unsupported confidence state.");
  if (input.sensitivity !== undefined && !["standard","restricted"].includes(input.sensitivity)) throw new TypeError("Unsupported sensitivity classification.");
  if (input.visibility === "owner_admin" && !["owner","admin"].includes(input.actor.role)) throw new TypeError("Owner/admin-only knowledge must be created by an owner or administrator.");
  if (input.confidence === "verified" && !["owner","admin","manager","reviewer"].includes(input.actor.role)) throw new TypeError("Only an authorised reviewer or manager can mark knowledge verified.");
  if (!STATUSES.has(input.status || "active")) throw new TypeError("Unsupported knowledge status.");
  if (input.visibility === "site_team" && input.scope.type !== "site") throw new TypeError("Site-team visibility is only valid for site-scoped knowledge.");
  if (input.sensitivity === "restricted" && input.visibility !== "owner_admin") throw new TypeError("Restricted knowledge must use owner/admin visibility.");
  const title = requireText(input.title,"Title",120);
  const content = requireText(input.content,"Content",2000);
  validateContent(title,content);
  const sourceRef = requireText(input.sourceRef,"Source reference",200);
  const permissionRef = requireText(input.permissionRef,"Permission reference",200);
  const sourceDate = input.sourceDate;
  const reviewBy = input.reviewBy;
  const expiresOn = input.expiresOn ?? null;
  validateDates({sourceDate,reviewBy,expiresOn});
  if (input.confidence === "verified" && !input.evidenceRef) throw new TypeError("Verified knowledge requires an evidence reference.");
  const evidenceRef = input.evidenceRef == null ? null : requireText(input.evidenceRef,"Evidence reference",200);
  const occurredAt = input.occurredAt;
  if (!validDateTime(occurredAt)) throw new TypeError("Occurred-at timestamp must include an explicit timezone offset.");
  return {
    tenantId,
    itemId: requireText(input.itemId,"Item ID",128),
    eventId: requireText(input.eventId,"Event ID",128),
    version: 1,
    previousVersion: null,
    knowledgeType: input.knowledgeType,
    key: input.key,
    scope: {type:input.scope.type,id:input.scope.id},
    title,
    content,
    ownerId: requireText(input.ownerId,"Knowledge owner",128),
    sourceRef,
    permissionRef,
    evidenceRef,
    sourceDate,
    reviewBy,
    expiresOn,
    visibility: input.visibility,
    sensitivity: input.sensitivity === "restricted" ? "restricted" : "standard",
    confidence: input.confidence,
    status: input.status || "active",
    actorId: input.actor.id,
    actorRole: input.actor.role,
    reason: requireText(input.reason || "Initial knowledge record","Reason",500),
    occurredAt
  };
}

/**
 * Append a new immutable version. The caller's history array is never mutated.
 * Scope and key remain stable; a correction is a new event, not an overwrite.
 */
export function appendKnowledgeVersion(history, update={}) {
  if (!Array.isArray(history)) throw new TypeError("Knowledge history must be an array.");
  const itemId = requireText(update.itemId,"Item ID",128);
  const tenantId = requireText(update.tenantId,"Tenant ID",128);
  const versions = history.filter(item => item.itemId === itemId && item.tenantId === tenantId);
  if (!versions.length) throw new RangeError("Knowledge item does not exist in this tenant.");
  const ordered = versions.slice().sort((a,b)=>a.version-b.version);
  const latest = ordered[ordered.length-1];
  if (new Set(ordered.map(x=>x.version)).size !== ordered.length || latest.version !== ordered.length) throw new Error("Knowledge history has a missing or duplicate version.");
  validateActor(update.actor,tenantId);
  const occurredAt = update.occurredAt;
  if (!validDateTime(occurredAt) || Date.parse(occurredAt) <= Date.parse(latest.occurredAt)) throw new RangeError("New knowledge events must have a later timezone-aware timestamp.");
  const reason = requireText(update.reason,"Change reason",500);
  const title = update.title === undefined ? latest.title : requireText(update.title,"Title",120);
  const content = update.content === undefined ? latest.content : requireText(update.content,"Content",2000);
  validateContent(title,content);
  const reviewBy = update.reviewBy === undefined ? latest.reviewBy : update.reviewBy;
  const expiresOn = update.expiresOn === undefined ? latest.expiresOn : update.expiresOn;
  const sourceDate = update.sourceDate === undefined ? latest.sourceDate : update.sourceDate;
  validateDates({sourceDate,reviewBy,expiresOn});
  const confidence = update.confidence === undefined ? latest.confidence : update.confidence;
  if (!CONFIDENCE.has(confidence)) throw new TypeError("Unsupported confidence state.");
  const evidenceRef = update.evidenceRef === undefined ? latest.evidenceRef : update.evidenceRef;
  if (confidence === "verified" && !evidenceRef) throw new TypeError("Verified knowledge requires an evidence reference.");
  const visibility = update.visibility === undefined ? latest.visibility : update.visibility;
  if (!VISIBILITY.has(visibility) || (visibility === "site_team" && latest.scope.type !== "site")) throw new TypeError("Invalid visibility for this knowledge scope.");
  if (visibility === "owner_admin" && !["owner","admin"].includes(update.actor.role)) throw new TypeError("Owner/admin-only knowledge must be changed by an owner or administrator.");
  const sensitivity = update.sensitivity === undefined ? latest.sensitivity : update.sensitivity;
  if (!["standard","restricted"].includes(sensitivity)) throw new TypeError("Unsupported sensitivity classification.");
  if (sensitivity === "restricted" && visibility !== "owner_admin") throw new TypeError("Restricted knowledge must use owner/admin visibility.");
  const status = update.status === undefined ? "active" : update.status;
  if (!STATUSES.has(status)) throw new TypeError("Unsupported knowledge status.");
  const next = {
    ...latest,
    eventId: requireText(update.eventId,"Event ID",128),
    version: latest.version + 1,
    previousVersion: latest.version,
    title,content,sourceDate,reviewBy,expiresOn,confidence,evidenceRef,visibility,sensitivity,status,
    sourceRef:update.sourceRef===undefined?latest.sourceRef:requireText(update.sourceRef,"Source reference",200),
    permissionRef:update.permissionRef===undefined?latest.permissionRef:requireText(update.permissionRef,"Permission reference",200),
    actorId:update.actor.id,
    actorRole:update.actor.role,
    reason,
    occurredAt
  };
  if (history.some(item => item.eventId === next.eventId)) throw new Error("Knowledge event ID must be unique.");
  return [...history,next];
}

function latestRecords(records) {
  const latest = new Map();
  for (const record of records) {
    const key = record.tenantId + "\n" + record.itemId;
    const old = latest.get(key);
    if (!old || record.version > old.version) latest.set(key,record);
  }
  return [...latest.values()];
}

export function assessKnowledge(records, asOf) {
  if (!Array.isArray(records) || !validDate(asOf)) throw new TypeError("Records and a valid as-of date are required.");
  const latest = latestRecords(records);
  const activeGroups = new Map();
  for (const item of latest) {
    if (item.status !== "active") continue;
    const groupKey = [item.tenantId,item.scope.type,item.scope.id,item.key].join("\n");
    const group = activeGroups.get(groupKey) || [];
    group.push(item);activeGroups.set(groupKey,group);
  }
  const conflicts = new Set();
  for (const group of activeGroups.values()) {
    if (new Set(group.map(item=>item.content)).size > 1) for (const item of group) conflicts.add(item.tenantId+"\n"+item.itemId);
  }
  return latest.map(item=>{
    let computedStatus = item.status;
    if (item.status === "active" && item.expiresOn && item.expiresOn < asOf) computedStatus = "expired";
    else if (item.status === "active" && item.reviewBy < asOf) computedStatus = "stale";
    else if (item.status === "active" && conflicts.has(item.tenantId+"\n"+item.itemId)) computedStatus = "conflicting";
    return {...item,computedStatus};
  });
}

function canView(item,actor) {
  if (item.visibility === "owner_admin") return actor.role === "owner" || actor.role === "admin";
  if (item.visibility === "site_team") return item.scope.type === "site" && Array.isArray(actor.siteIds) && actor.siteIds.includes(item.scope.id);
  return true;
}

export function searchKnowledge(records,{tenantId,actor,query="",scopeId=null,includeInactive=false,asOf}={}) {
  if (!Array.isArray(records)) throw new TypeError("Knowledge records must be an array.");
  validateActor(actor,tenantId);
  const needle = typeof query === "string" ? query.trim().toLocaleLowerCase("en") : "";
  return assessKnowledge(records,asOf)
    .filter(item=>item.tenantId===tenantId&&canView(item,actor))
    .filter(item=>!scopeId||item.scope.id===scopeId)
    .filter(item=>includeInactive||["active","stale","conflicting"].includes(item.computedStatus))
    .filter(item=>!needle||(item.title+" "+item.content+" "+item.key+" "+item.knowledgeType).toLocaleLowerCase("en").includes(needle))
    .sort((a,b)=>b.occurredAt.localeCompare(a.occurredAt));
}
