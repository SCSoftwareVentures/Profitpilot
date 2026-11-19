import {createHash,randomUUID} from "node:crypto";
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const id=x=>typeof x==="string"&&uuid.test(x),hash=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const exact=(b,keys)=>b&&typeof b==="object"&&!Array.isArray(b)&&Object.keys(b).length===keys.length&&keys.every(k=>Object.hasOwn(b,k));
export const participantOps=["view","photo","upload","evidence","ack","appeal","repair"];
export function validParticipantRequest(op,b){
 if(op==="view")return exact(b,[]);
 if(!id(b?.caseId))return false;
 if(op==="photo")return exact(b,["caseId","photoId","source"])&&id(b.photoId)&&["dispute","completion"].includes(b.source);
 if(op==="upload")return exact(b,["caseId","mediaType","content"])&&["image/png","image/jpeg"].includes(b.mediaType)&&typeof b.content==="string"&&b.content.length>=12&&b.content.length<=2796204&&/^[A-Za-z0-9+/]+={0,2}$/.test(b.content);
 if(!hash(b.stateDigest)||typeof b.reason!=="string"||b.reason.trim().length<10||b.reason.length>2000||b.reason.includes("\0"))return false;
 const base=["caseId","stateDigest","reason"];
 if(op==="evidence")return exact(b,base);
 if(op==="ack"||op==="appeal")return exact(b,[...base,"decisionId","payoutCents","refundCents"])&&id(b.decisionId)&&[b.payoutCents,b.refundCents].every(x=>Number.isSafeInteger(x)&&x>=0);
 if(op==="repair")return exact(b,[...base,"action","dueEpoch","photoId"])&&["propose","accept_plan","submit_repair","accept_repair","escalate"].includes(b.action)&&(b.dueEpoch===null||Number.isSafeInteger(b.dueEpoch))&&(b.photoId===null||id(b.photoId));
 return false;
}
export async function participantRequest({invoke,scanner,tenantId,milestoneId,actorId,op,body}){
 if(!id(tenantId)||!id(milestoneId)||!id(actorId)||!validParticipantRequest(op,body))throw Object.assign(Error("Invalid dispute request"),{status:400});
 let payload=body;
 if(op==="upload"){
  if(typeof scanner?.attest!=="function")return null;
  const scope=await invoke("view",{});if(scope?.case?.caseId!==body.caseId||!["open","appealed"].includes(scope.case.status))return null;
  const content=Buffer.from(body.content,"base64");if(content.length<8||content.length>2097152||content.toString("base64")!==body.content)throw Object.assign(Error("Invalid evidence"),{status:400});
  const photoId=randomUUID(),att=await scanner.attest({photoId,tenantId,milestoneId,caseId:body.caseId,actorId,mediaType:body.mediaType,content:Buffer.from(content)});
  if(!att||!Buffer.isBuffer(att.content)||att.content.length>2097152||att.originalDigest!==createHash("sha256").update(content).digest("hex")||att.digest!==createHash("sha256").update(att.content).digest("hex")||att.originalMediaType!==body.mediaType||!Number.isSafeInteger(att.exp)||typeof att.signature!=="string")return null;
  payload={caseId:body.caseId,photoId,digest:att.digest,content:att.content.toString("base64"),originalDigest:att.originalDigest,originalMediaType:att.originalMediaType,scanExpiry:att.exp,scanSignature:att.signature};
 }
 const result=await invoke(op,payload);
 if(op==="photo"&&result){const b=Buffer.from(result.content,"base64");if(result.photoId!==body.photoId||b.length<8||b.length>2097152||b.toString("base64")!==result.content||b.subarray(0,8).toString("hex")!=="89504e470d0a1a0a"||createHash("sha256").update(b).digest("hex")!==result.digest)throw Error("Evidence integrity failure");}
 return result;
}
