import {createHash} from "node:crypto";
import {createRemoteJWKSet,jwtVerify} from "jose";
const uuid=x=>typeof x==="string"&&/^[a-f0-9]{8}-[a-f0-9]{4}-[1-8][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(x);
const ref=x=>typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(x);
const fields=["iss","aud","sub","jti","iat","nbf","exp","tenantId","caseId","evidenceId","claimId","jobReference","claimedPartyRole","keySpkiSha256","permission"];
let cachedUrl,cachedJwks;
export const digest=x=>createHash("sha256").update(x).digest("hex");
export function validIssuerRequest(b){return b!==null&&typeof b==="object"&&!Array.isArray(b)&&
 Object.keys(b).length===2&&Object.hasOwn(b,"clientRequestId")&&Object.hasOwn(b,"attestationJwt")&&
 uuid(b.clientRequestId)&&typeof b.attestationJwt==="string"&&b.attestationJwt.length>=100&&
 b.attestationJwt.length<=4096&&/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(b.attestationJwt);}
export function issuerSettings(env=process.env){
 const issuer=env.SECUREPAY_AUTHORITY_ISSUER,audience=env.SECUREPAY_AUTHORITY_AUDIENCE,url=env.SECUREPAY_AUTHORITY_JWKS_URL;
 if(!issuer||!audience||!url)throw new Error("Independent issuer not configured");
 let i,u;try{i=new URL(issuer);u=new URL(url);}catch{throw new Error("Invalid issuer configuration");}
 const localhost=env.NODE_ENV==="test"&&u.protocol==="http:"&&["localhost","127.0.0.1","[::1]"].includes(u.hostname);
 if(i.protocol!=="https:"||i.username||i.password||i.hash||i.search||
 (u.protocol!=="https:"&&!localhost)||u.username||u.password||u.hash||
 !ref(audience)||env.AUTH_ISSUER===issuer||env.AUTH_JWKS_URL===url)
  throw new Error("Independent issuer configuration is unsafe");
 return {issuer,audience,jwksUrl:u};
}
export function validateIssuerScope(p,scope,now=Math.floor(Date.now()/1000)){
 return Boolean(p&&scope&&Object.keys(p).length===fields.length&&fields.every(k=>Object.hasOwn(p,k))&&
 ref(p.sub)&&uuid(p.jti)&&Number.isSafeInteger(p.iat)&&Number.isSafeInteger(p.nbf)&&Number.isSafeInteger(p.exp)&&
 p.exp>p.iat&&p.exp-p.iat<=600&&p.nbf>=p.iat-5&&p.nbf<=p.iat+5&&
 p.exp>now&&p.iat<=now+5&&p.permission==="synthetic_job_claim_review_only"&&
 ["customer","tradesperson"].includes(p.claimedPartyRole)&&
 [p.tenantId,p.caseId,p.evidenceId,p.claimId].every(uuid)&&ref(p.jobReference)&&
 typeof p.keySpkiSha256==="string"&&/^[a-f0-9]{64}$/.test(p.keySpkiSha256)&&
 ["tenantId","caseId","evidenceId","claimId","jobReference","claimedPartyRole","keySpkiSha256"].every(k=>p[k]===scope[k]));
}
export async function verifyIssuerAttestation(jwt,settings,scope){
 if(typeof jwt!=="string"||jwt.length>4096)throw new TypeError("Bounded issuer token required");
 if(cachedUrl!==settings.jwksUrl.href){cachedJwks=createRemoteJWKSet(settings.jwksUrl,{timeoutDuration:5000,cooldownDuration:30000});cachedUrl=settings.jwksUrl.href;}
 const {payload}=await jwtVerify(jwt,cachedJwks,{issuer:settings.issuer,audience:settings.audience,algorithms:["RS256","ES256"],
  requiredClaims:["sub","iat","nbf","exp","jti"],maxTokenAge:600,clockTolerance:5});
 if(!validateIssuerScope(payload,scope))throw new Error("Invalid bounded issuer/job scope");
 return {issuer:settings.issuer,jti:payload.jti,issuedAt:new Date(payload.iat*1000),expiresAt:new Date(payload.exp*1000),
  subjectHash:digest(payload.sub),tokenHash:digest(jwt)};
}
