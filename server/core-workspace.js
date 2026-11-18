import {isIsoDate} from "../src/engine.js";
const SETUP=/^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const FIELDS=["businessName","siteName","customerName","effectiveFrom","price","currency","taxBasis","billingBasis"];
const label=x=>typeof x==="string"&&x.length<=120&&x===x.trim()&&/^[A-Za-z0-9][A-Za-z0-9 .&'()-]{0,119}$/.test(x);
export const validSetupId=x=>typeof x==="string"&&SETUP.test(x);
export function workspaceInput(body){
 if(!body||typeof body!=="object"||Array.isArray(body)||Object.keys(body).length!==FIELDS.length+1||
 !["setupId",...FIELDS].every(k=>Object.hasOwn(body,k)&&typeof body[k]==="string")||
 !validSetupId(body.setupId)||!["businessName","siteName","customerName"].every(k=>label(body[k]))||
 !/^20\d{2}-\d{2}-\d{2}$/.test(body.effectiveFrom)||!isIsoDate(body.effectiveFrom)||
 !/^(0|[1-9]\d{0,11})\.\d{2}$/.test(body.price)||body.currency!=="AUD"||body.billingBasis!=="monthly"||
 !["gst_inclusive","gst_exclusive","no_gst","unknown"].includes(body.taxBasis))return null;
 return {setupId:body.setupId.toLowerCase(),data:Object.fromEntries(FIELDS.map(k=>[k,body[k]]))};
}
// New functionality is deliberately synthetic/non-production until separately
// approved. No environment flag silently opens the route.
export function coreWorkspaceGate(env=process.env){
 const closed=env.NODE_ENV==="production";
 return (_req,res,next)=>closed?res.status(503).json({error:"Production workspace onboarding is not approved"}):next();
}
