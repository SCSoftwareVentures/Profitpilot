// Release interlock for the unapproved engineering candidate. No environment
// toggle or supplied document may activate a customer-facing operation.
// Health and bounded security probes remain available for synthetic CI.
export function productionReleaseGate(env=process.env){
 const locked=env.NODE_ENV==="production";
 return (_req,res,next)=>{
  if(!locked)return next();
  res.set("Cache-Control","no-store");
  return res.status(503).json({error:"Live processing is not approved",code:"RELEASE_CLOSED"});
 };
}
