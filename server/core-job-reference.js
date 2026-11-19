// Synthetic, short-lived, signed READ-ONLY context; never an authorization for money.
import {createPrivateKey,createPublicKey,sign,verify,createHash} from "node:crypto";
import {isIsoDate} from "../src/engine.js";
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(x);
const hash=x=>typeof x==="string"&&/^[a-f0-9]{64}$/.test(x);
const format="profitpilot-core-job-reference-v1",ttl=120;
const exact=(x,fields)=>x&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===fields.length&&fields.every(f=>Object.hasOwn(x,f));
const fields=["format","tenantId","jobId","contractId","siteId","baselineId","serviceDate","baselinePrice","taxBasis","currency","status","readinessStatus","issuedAt","expiresAt"];
const allowed=env=>["development","test"].includes(env.NODE_ENV)&&env.CORE_JOB_REFERENCE_ENABLED==="true";
function bytes(s,max){
 if(typeof s!=="string"||s.length>max||!/^[A-Za-z0-9_-]+$/.test(s))throw Error("Invalid reference encoding");
 const b=Buffer.from(s,"base64url");if(b.toString("base64url")!==s)throw Error("Noncanonical reference encoding");return b;
}
function key(env,name,type){
 const k=type==="pkcs8"?createPrivateKey({key:bytes(env[name],256),format:"der",type}):createPublicKey({key:bytes(env[name],256),format:"der",type});
 if(k.asymmetricKeyType!=="ed25519")throw Error("Independent Ed25519 reference key required");return k;
}
export function jobReferenceSigner(env=process.env){
 if(!allowed(env))return null;
 return key(env,"CORE_JOB_REFERENCE_SIGNING_KEY","pkcs8");
}
export function jobReferenceVerifier(env=process.env){
 if(env.CORE_JOB_REFERENCE_SIGNING_KEY!==undefined)throw Error("Core reference signing key forbidden in completion authority");
 if(!allowed(env))return null;
 return key(env,"CORE_JOB_REFERENCE_PUBLIC_KEY","spki");
}
function canonical(p){
 if(!exact(p,fields)||p.format!==format||![p.tenantId,p.jobId,p.contractId,p.siteId,p.baselineId].every(uuid)||
 !isIsoDate(p.serviceDate)||typeof p.baselinePrice!=="string"||!/^(0|[1-9][0-9]{0,11})\.[0-9]{2}$/.test(p.baselinePrice)||
 !["gst_inclusive","gst_exclusive","no_gst"].includes(p.taxBasis)||p.currency!=="AUD"||
 !["planned","in_progress","completed","cancelled"].includes(p.status)||!["ready","not_ready"].includes(p.readinessStatus)||
 !Number.isSafeInteger(p.issuedAt)||p.issuedAt<1||!Number.isSafeInteger(p.expiresAt)||p.expiresAt!==p.issuedAt+ttl)
 throw Error("Invalid reference payload");
 return Buffer.from(JSON.stringify(fields.map(f=>p[f])));
}
export function issueJobReference({tenantId,jobId,job,signingKey,now=Math.floor(Date.now()/1000)}){
 if(!signingKey||job?.jobId!==jobId)throw Error("Reference scope unavailable");
 const p={format,tenantId,jobId,contractId:job.contractId,siteId:job.siteId,baselineId:job.baselineId,serviceDate:job.serviceDate,
 baselinePrice:job.baselinePrice,taxBasis:job.taxBasis,currency:job.currency,status:job.status,readinessStatus:job.readinessStatus,issuedAt:now,expiresAt:now+ttl};
 const raw=canonical(p);
 return {reference:raw.toString("base64url")+"."+sign(null,raw,signingKey).toString("base64url"),expiresAt:p.expiresAt,mode:"sandbox",moneyMoved:false};
}
export function verifyJobReference({reference,tenantId,jobId,publicKey,now=Math.floor(Date.now()/1000)}){
 if(!publicKey||!uuid(tenantId)||!uuid(jobId)||typeof reference!=="string"||reference.length>2048)throw Error("Reference unavailable");
 const parts=reference.split(".");if(parts.length!==2)throw Error("Invalid reference");
 const raw=bytes(parts[0],1900),signature=bytes(parts[1],88);
 if(signature.length!==64||!verify(null,raw,publicKey,signature))throw Error("Invalid reference signature");
 const values=JSON.parse(raw.toString("utf8"));if(!Array.isArray(values)||values.length!==fields.length)throw Error("Invalid reference");
 const p=Object.fromEntries(fields.map((f,i)=>[f,values[i]]));
 if(!canonical(p).equals(raw)||p.tenantId!==tenantId||p.jobId!==jobId||!Number.isSafeInteger(now)||p.issuedAt>now+5||p.expiresAt<=now)throw Error("Stale or mismatched reference");
 return p;
}
export function projectJobReference(p,view){
 canonical(p);
 if(!view||view.jobId!==p.jobId)throw Error("Quote scope unavailable");
 const q=view.quote;
 if(q!==null&&(!q||!uuid(q.quoteId)||!hash(q.quoteDigest)||!Number.isInteger(q.revision)||q.revision<1||q.revision>100||
 typeof q.totalCents!=="string"||!/^[1-9][0-9]{0,15}$/.test(q.totalCents)||BigInt(q.totalCents)>9007199254740991n))throw Error("Invalid quote view");
 const plan=view.plan;
 if(plan!==null&&(!plan||!q||!uuid(plan.planId)||!hash(plan.planDigest)||!["offered","accepted"].includes(plan.status)))throw Error("Invalid plan view");
 return {mode:"sandbox",moneyMoved:false,paymentAuthorized:false,jobReferenceVerified:true,jobId:p.jobId,contractId:p.contractId,siteId:p.siteId,baselineId:p.baselineId,
 serviceDate:p.serviceDate,jobStatus:p.status,readinessStatus:p.readinessStatus,
 coreBaseline:{amount:p.baselinePrice,currency:p.currency,taxBasis:p.taxBasis,notAJobQuote:true},
 quote:q?{quoteId:q.quoteId,quoteDigest:q.quoteDigest,revision:q.revision,totalCents:q.totalCents}:null,
 plan:plan?{planId:plan.planId,planDigest:plan.planDigest,status:plan.status}:null,
 snapshotExpiresAt:p.expiresAt,referenceDigest:createHash("sha256").update(canonical(p)).digest("hex"),
 warning:"Read-only snapshot. Contract baseline and customer quote may cover different periods or tax bases. Not proof of shared party identity, current readiness, consent, safety, funds or payment authority."};
}
