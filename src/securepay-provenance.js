import {createHash} from "node:crypto";
// All provenance is operator-REPORTED. This module cannot verify a source identity.
const uuid=x=>typeof x==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(x);
const ref=x=>typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(x);
export const ORIGIN_TYPES=Object.freeze(["reported_customer","reported_business","reported_third_party","operator_observed","unknown"]);
export const ACQUISITION_TYPES=Object.freeze(["operator_relay","document_reference_only","unknown"]);
const fields=["clientRequestId","reportedOrigin","acquisitionMethod","sourceReference"];
export function validProvenanceRequest(b){
 return b!==null&&typeof b==="object"&&!Array.isArray(b)&&
  Object.keys(b).length===fields.length&&fields.every(k=>Object.hasOwn(b,k))&&
  uuid(b.clientRequestId)&&ORIGIN_TYPES.includes(b.reportedOrigin)&&
  ACQUISITION_TYPES.includes(b.acquisitionMethod)&&ref(b.sourceReference);
}
// The digest fingerprints self-reported METADATA only, not file bytes, source authenticity,
// proof of party-to-job identity, or trusted evidence custody.
export function reportedMetadataDigest(input){
 const keys=["tenantId","caseId","evidenceId","actorId","jobReference","evidenceType",
  "evidenceReference","reportedOrigin","acquisitionMethod","sourceReference"];
 if(!input||keys.some(k=>typeof input[k]!=="string")||
  ![input.tenantId,input.caseId,input.evidenceId,input.actorId].every(uuid)||
  ![input.jobReference,input.evidenceReference,input.sourceReference].every(ref)||
  !["claim_reported","business_response_reported","operator_review_note","rectification_reported","appeal_reported"].includes(input.evidenceType)||
  !ORIGIN_TYPES.includes(input.reportedOrigin)||!ACQUISITION_TYPES.includes(input.acquisitionMethod))
  throw new TypeError("Invalid synthetic provenance metadata");
 return createHash("sha256").update(JSON.stringify(["securepay-operator-provenance-v1",...keys.map(k=>input[k])])).digest("hex");
}
export function sameReportedMetadata(row,b){
 return row?.reported_origin===b.reportedOrigin&&row?.acquisition_method===b.acquisitionMethod&&
  row?.source_reference===b.sourceReference;
}
