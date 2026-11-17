// Production gate: independently signed, time-limited, exact-build release evidence.
// The signatures attest operator review; they are not independent proof of the underlying evidence.
import {createHash,createPublicKey,verify} from "node:crypto";
import {readFileSync,statSync} from "node:fs";
export const requiredReleaseControls=Object.freeze([
 "provider_identity_mfa_recovery","tenant_and_object_isolation","database_runtime_privileges",
 "encryption_and_key_custody","secure_file_boundary","dependency_secret_container_scans",
 "independent_backup_restore","monitoring_incident_exercise","privacy_retention_and_processors",
 "independent_penetration_retest","operational_risk_acceptance"
]);
const sha=/^[a-f0-9]{64}$/;
const revision=/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/;
const deployment=/^[A-Za-z0-9._-]{3,128}$/;
const exactKeys=(obj,keys)=>obj!==null&&typeof obj==="object"&&!Array.isArray(obj)&&Object.keys(obj).sort().join("|")===[...keys].sort().join("|");
function reject(){throw Error("Production release evidence is missing, invalid, stale or not approved");}
export function releaseConfigDigest(env){
 const db=new URL(env.DATABASE_URL);
 // Bind non-secret security-critical configuration. Secret material and passwords never enter evidence.
 const configuration={dbHost:db.hostname,dbPort:db.port,dbName:db.pathname,dbRole:db.username,databaseSsl:env.DATABASE_SSL,
 issuer:env.AUTH_ISSUER,audience:env.AUTH_AUDIENCE,jwksUrl:env.AUTH_JWKS_URL,acr:env.AUTH_STEP_UP_ACR,
 mfaMaxAge:String(env.AUTH_STEP_UP_MAX_AGE_SECONDS??300),cors:(env.CORS_ORIGIN||"").split(",").map(v=>v.trim()).sort(),tenantKeyId:env.TENANT_CONTEXT_HMAC_KEY_ID||"primary"};
 return createHash("sha256").update(JSON.stringify(configuration)).digest("hex");
}
function key(value){
 if(typeof value!=="string"||value.length>256||!/^[A-Za-z0-9_-]+$/.test(value))reject();
 const raw=Buffer.from(value,"base64url");if(raw.toString("base64url")!==value)reject();
 const k=createPublicKey({key:raw,format:"der",type:"spki"});
 if(k.asymmetricKeyType!=="ed25519")reject();
 return k;
}
function signature(value){
 if(typeof value!=="string"||!/^[A-Za-z0-9_-]{86}$/.test(value))reject();
 const raw=Buffer.from(value,"base64url");if(raw.length!==64||raw.toString("base64url")!==value)reject();
 return raw;
}
export function releaseSigningBytes(payload,role){
 if(!["technical","privacy"].includes(role)||typeof payload!=="string"||Buffer.byteLength(payload)>32768)reject();
 return Buffer.from("profitpilot-release-approval-v1\n"+role+"\n"+payload,"utf8");
}
export function verifyReleaseApproval(document,{buildRevision,deploymentId,configurationDigest,technicalPublicKey,privacyPublicKey,now=Date.now()}){
 try{
  if(!revision.test(buildRevision||"")||!deployment.test(deploymentId||"")||!sha.test(configurationDigest||"")||
    !exactKeys(document,["payload","technicalSignature","privacySignature"])||typeof document.payload!=="string"||Buffer.byteLength(document.payload)>32768)reject();
  const technical=key(technicalPublicKey),privacy=key(privacyPublicKey);
  if(technical.export({format:"der",type:"spki"}).equals(privacy.export({format:"der",type:"spki"})))reject();
  if(!verify(null,releaseSigningBytes(document.payload,"technical"),technical,signature(document.technicalSignature))||
     !verify(null,releaseSigningBytes(document.payload,"privacy"),privacy,signature(document.privacySignature)))reject();
  const p=JSON.parse(document.payload);
  if(!exactKeys(p,["version","buildRevision","deploymentId","configurationDigest","issuedAt","expiresAt","controls"])||
    p.version!==1||p.buildRevision!==buildRevision||p.deploymentId!==deploymentId||p.configurationDigest!==configurationDigest)reject();
  const issued=Date.parse(p.issuedAt),expires=Date.parse(p.expiresAt),max=30*86400000;
  if(!Number.isSafeInteger(now)||!Number.isFinite(issued)||!Number.isFinite(expires)||new Date(issued).toISOString()!==p.issuedAt||new Date(expires).toISOString()!==p.expiresAt||
     issued>now||expires<=now||expires<=issued||expires-issued>max||now-issued>max)reject();
  if(!exactKeys(p.controls,requiredReleaseControls))reject();
  for(const id of requiredReleaseControls){
   const control=p.controls[id];
   if(!exactKeys(control,["status","evidenceSha256"])||control.status!=="verified"||!sha.test(control.evidenceSha256||"")||/^0+$/.test(control.evidenceSha256))reject();
  }
  return Object.freeze({verified:true,buildRevision,expiresAt:expires});
 }catch{reject();}
}
export function readProductionReleaseApproval(env=process.env){
 if(env.NODE_ENV!=="production")return null;
 try{
  const file=env.PROFITPILOT_RELEASE_APPROVAL_FILE;
  if(typeof file!=="string"||!file.startsWith("/")||statSync(file).size>65536)reject();
  const buildRevision=readFileSync(new URL("../BUILD_REVISION",import.meta.url),"utf8").trim();
  const document=JSON.parse(readFileSync(file,"utf8"));
  return verifyReleaseApproval(document,{buildRevision,deploymentId:env.PROFITPILOT_DEPLOYMENT_ID,configurationDigest:releaseConfigDigest(env),
   technicalPublicKey:env.PROFITPILOT_TECHNICAL_APPROVAL_PUBLIC_KEY,privacyPublicKey:env.PROFITPILOT_PRIVACY_APPROVAL_PUBLIC_KEY});
 }catch{reject();}
}
export function releaseStillApproved(approval,now=Date.now()){return approval===null||approval.verified===true&&Number.isSafeInteger(now)&&now<approval.expiresAt;}
