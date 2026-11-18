import { createPublicKey, createHash, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const POLICY = "AU-STRICT-1";
export const REQUIRED_GATES = Object.freeze(Array.from({length:12}, (_,i) => "AU"+String(i+1).padStart(2,"0")));
const hex = (value,length) => typeof value === "string" && value.length === length && /^[0-9a-f]+$/.test(value);
const shape = (value, keys) => value !== null && typeof value === "object" && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(k=>Object.hasOwn(value,k));
const iso = value => typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
  Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
const fail = () => { throw new Error("Australian legal release gate denied"); };
const keyFrom = value => value?.type==="public" ? value : createPublicKey(value);
const fingerprint = key => createHash("sha256").update(key.export({type:"spki",format:"der"})).digest("hex");
const sigBytes = value => {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]{86}==$/.test(value)) fail();
  const bytes = Buffer.from(value,"base64");
  if(bytes.length!==64 || bytes.toString("base64")!==value) fail();
  return bytes;
};

// Exact, ordered, domain-separated statement. No free-text personal data.
export function canonicalApproval(record) {
  if(!shape(record,["policy","commit","scopeSha256","approvedAt","expiresAt","gates"]) ||
    record.policy!==POLICY || !hex(record.commit,40) || !hex(record.scopeSha256,64) ||
    !iso(record.approvedAt) || !iso(record.expiresAt) ||
    !Array.isArray(record.gates) || record.gates.length!==REQUIRED_GATES.length) fail();
  const gates=record.gates.map((gate,i)=>{
    if(!shape(gate,["id","status","evidenceSha256"]) || gate.id!==REQUIRED_GATES[i] ||
      gate.status!=="approved" || !hex(gate.evidenceSha256,64) || /^0+$/.test(gate.evidenceSha256)) fail();
    return [gate.id,gate.status,gate.evidenceSha256];
  });
  return Buffer.from(JSON.stringify(["profitpilot-au-legal-release-v1",record.policy,record.commit,record.scopeSha256,record.approvedAt,record.expiresAt,gates]),"utf8");
}

// Expected scope/commit and both trust fingerprints must come from independently
// managed release configuration, never from the untrusted approval bundle.
export function verifyAustralianRelease(bundle, expected, trust, now=Date.now()) {
  if(!shape(bundle,["record","counselSignature","ownerSignature"]) ||
    !shape(expected,["commit","scopeSha256"]) ||
    !shape(trust,["counselKey","ownerKey","counselFingerprint","ownerFingerprint"]) ||
    !Number.isFinite(now)) fail();
  const statement=canonicalApproval(bundle.record);
  const r=bundle.record, approved=Date.parse(r.approvedAt), expires=Date.parse(r.expiresAt);
  if(r.commit!==expected.commit || r.scopeSha256!==expected.scopeSha256 ||
    !hex(expected.commit,40) || !hex(expected.scopeSha256,64) || /^0+$/.test(expected.scopeSha256) ||
    approved>now || expires<=now || expires<=approved || expires-approved>90*86400000) fail();
  const counsel=keyFrom(trust.counselKey), owner=keyFrom(trust.ownerKey);
  const c=fingerprint(counsel), o=fingerprint(owner);
  if(counsel.asymmetricKeyType!=="ed25519" || owner.asymmetricKeyType!=="ed25519" ||
    counsel.type!=="public" || owner.type!=="public" || c===o ||
    c!==trust.counselFingerprint || o!==trust.ownerFingerprint) fail();
  if(!verify(null,statement,counsel,sigBytes(bundle.counselSignature)) ||
    !verify(null,statement,owner,sigBytes(bundle.ownerSignature))) fail();
  return true;
}

if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    if(process.argv.length!==9) fail();
    const [, , bundlePath, commit, scopeSha256, counselPath, ownerPath, counselFingerprint, ownerFingerprint]=process.argv;
    const bytes=readFileSync(bundlePath);
    if(bytes.length>32768) fail();
    verifyAustralianRelease(JSON.parse(bytes.toString("utf8")),{commit,scopeSha256},{
      counselKey:readFileSync(counselPath),ownerKey:readFileSync(ownerPath),counselFingerprint,ownerFingerprint
    });
    console.log("Australian legal evidence gate: signed approval verified; this is not a legal opinion or deployment authorization");
  } catch {
    console.error("Australian legal evidence gate: DENIED");
    process.exitCode=1;
  }
}
