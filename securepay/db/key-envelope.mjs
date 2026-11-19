import {createHmac} from "node:crypto";
export function validKeyId(id){return typeof id==="string"&&/^[a-z0-9-]{1,32}$/.test(id);}
export function signEnvelope(key,id,payload){
 if(!Buffer.isBuffer(key)||key.length!==32||!validKeyId(id)||typeof payload!=="string")throw Error("Signing authority unavailable");
 return id+"."+createHmac("sha256",key).update(payload+":"+id).digest("hex");
}
