import {createHmac,randomBytes} from "node:crypto";
import {sessionDigest} from "./db.js";
import {hasRecentMfa} from "./auth.js";

// Production intake stays closed until independent scanner, privacy and
// operational acceptance. No environment switch silently enables it.
export function importIntakeGate(env=process.env){
 const closed=env.NODE_ENV==="production";
 return (_req,res,next)=>closed?res.status(503).json({error:"Production import intake is not approved"}):next();
}

// Only the verified JWT identity after step-up can produce this proof.
// Scope includes tenant, batch and session; no caller-supplied signature.
export function promotionProof(tenant,batch,identity,env=process.env,now=Math.floor(Date.now()/1000)){
 const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/;
 const secret=env.TENANT_CONTEXT_HMAC_SECRET||"",key=env.TENANT_CONTEXT_HMAC_KEY_ID||"primary";
 if(!uuid.test(tenant)||!uuid.test(batch)||!hasRecentMfa(identity,now)||
 typeof identity.subject!=="string"||identity.subject.length<1||identity.subject.length>255||/\p{C}/u.test(identity.subject)||
 identity.issuedAt>now+5||identity.issuedAt<now-905||
 !/^[0-9a-f]{64,128}$/i.test(secret)||secret.length%2||
 !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(key))throw Object.assign(new Error("Promotion authority unavailable"),{status:403});
 const args=[String(identity.authTime),String(identity.issuedAt),sessionDigest(identity.sessionId),String(now+20),randomBytes(16).toString("hex"),key];
 const sig=createHmac("sha256",Buffer.from(secret,"hex")).update(["profitpilot-promotion-v1",tenant,batch,identity.subject,...args].join("\n")).digest("hex");
 return [tenant,batch,...args,sig];
}
