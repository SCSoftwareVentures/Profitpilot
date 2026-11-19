// Draft PIN credential primitives. Pepper must be a protected server secret,
// not a database column, never committed or included in logs.
import {createHmac,randomBytes,scrypt,timingSafeEqual} from "node:crypto";
import {promisify} from "node:util";
const derive=promisify(scrypt);
const pinFormat=/^[0-9]{6}$/;
const hexSalt=/^[0-9a-f]{32}$/;
const hexHash=/^[0-9a-f]{64}$/;
function input({tenantId,customerId,pin,pepper}) {
  if(!Buffer.isBuffer(pepper)||pepper.length<32) throw new Error("PIN protection unavailable");
  if(![tenantId,customerId].every(v=>typeof v==="string"&&v.length>0)) throw new Error("Invalid PIN scope");
  if(typeof pin!=="string"||!pinFormat.test(pin)) return null;
  return createHmac("sha256",pepper).update(JSON.stringify(["securepay-pin-v1",tenantId,customerId,pin])).digest();
}
async function hash(secret,salt) {
  try {return await derive(secret,Buffer.from(salt,"hex"),32,{N:32768,r:8,p:3,maxmem:64*1024*1024});}
  finally {secret.fill(0);}
}
// Enrollment must be invoked only after separate authenticated step-up.
// Enrollment/reset authorization and pepper rotation are not implemented here.
export async function createPinCredential(scope) {
  const secret=input(scope);
  if(!secret)throw new Error("PIN must contain six digits");
  const salt=randomBytes(16).toString("hex");
  const digest=await hash(secret,salt);
  try {return {salt,pinHash:digest.toString("hex")};}
  finally {digest.fill(0);}
}
export async function verifyPinCredential(scope,credential) {
  const secret=input(scope);
  if(!secret)return false;
  if(!credential||!hexSalt.test(credential.salt??"")||!hexHash.test(credential.pinHash??"")){
    secret.fill(0);return false;
  }
  const expected=Buffer.from(credential.pinHash,"hex"),actual=await hash(secret,credential.salt);
  try{return timingSafeEqual(actual,expected);}
  finally{actual.fill(0);expected.fill(0);}
}
