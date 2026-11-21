import {createHash} from "node:crypto";
export const MAX_CUSTODY_BYTES=512*1024;
const uuid=s=>typeof s==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const hex=s=>typeof s==="string"&&/^[a-f0-9]{64}$/.test(s);
export const mediaTypes=Object.freeze(["text/plain","application/pdf","image/png","image/jpeg"]);
export function validCustodyHeaders({clientRequestId,declaredSha256,mediaType,contentEncoding}){
 return uuid(clientRequestId)&&hex(declaredSha256)&&mediaTypes.includes(mediaType)&&
 (!contentEncoding||contentEncoding.toLowerCase()==="identity");
}
export function verifyCustodyBytes(bytes,declaredSha256,mediaType){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>MAX_CUSTODY_BYTES)throw new TypeError("Evidence bytes outside scanner limit");
 if(!hex(declaredSha256)||!mediaTypes.includes(mediaType))throw new TypeError("Invalid evidence metadata");
 if(mediaType==="text/plain"){
  let v;try{v=new TextDecoder("utf-8",{fatal:true}).decode(bytes);}catch{throw new TypeError("Text evidence must be valid UTF-8");}
  if(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F\u202A-\u202E\u2066-\u2069]/u.test(v))
   throw new TypeError("Disallowed text control characters");
 }else if(mediaType==="application/pdf"){
  if(bytes.length<12||!bytes.subarray(0,8).toString("latin1").startsWith("%PDF-")||
   !bytes.subarray(Math.max(0,bytes.length-1024)).includes(Buffer.from("%%EOF")))
   throw new TypeError("PDF signature or trailer missing");
 }else if(mediaType==="image/png"){
  if(bytes.length<24||!bytes.subarray(0,8).equals(Buffer.from("89504e470d0a1a0a","hex"))||
   !bytes.subarray(bytes.length-8,bytes.length-4).equals(Buffer.from("49454e44","hex")))
   throw new TypeError("PNG signature or trailer missing");
 }else if(mediaType==="image/jpeg"){
  if(bytes.length<6||bytes[0]!==0xff||bytes[1]!==0xd8||bytes[2]!==0xff||bytes.at(-2)!==0xff||bytes.at(-1)!==0xd9)
   throw new TypeError("JPEG signature or trailer missing");
 }
 const sha256=createHash("sha256").update(bytes).digest("hex");
 if(sha256!==declaredSha256)throw new TypeError("Evidence SHA-256 mismatch");
 return {sha256,byteCount:bytes.length,mediaType,receivedByteIntegrityVerified:true,
  sourceAuthenticityVerified:false,malwareSafetyIndependentlyVerified:false};
}
export function sameCustodyReceipt(row,request,actor){
 return row?.client_request_id===request.clientRequestId&&row?.received_by===actor&&
 row?.sha256===request.sha256&&row?.media_type===request.mediaType;
}
