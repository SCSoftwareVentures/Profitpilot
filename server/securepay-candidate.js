// Only synthetic development/test traffic may reach the independent authority.
export async function mountSecurePayCandidate(app,env=process.env){
 const path="/v1/securepay";
 if(env.SECUREPAY_SANDBOX_ENABLED!=="true"||!["development","test"].includes(env.NODE_ENV)){
  app.use(path,(_req,res)=>res.status(404).json({error:"Not found"}));
  return;
 }
 const {createSecurePayGateway}=await import("./securepay-gateway.js");
 const gateway=createSecurePayGateway(env);
 app.use(path,(req,res,next)=>{
  // Preserve the hardened core HTTP limits. Evidence uploads need a separate
  // reviewed admission path; they are not enabled through this shared listener.
  if(req.method==="POST"&&req.path.endsWith("/case-upload"))return res.status(413).json({error:"Evidence upload unavailable on combined candidate"});
  const encoding=req.headers["content-encoding"];
  if(encoding!==undefined&&encoding.toLowerCase()!=="identity")return res.status(415).json({error:"Unsupported content encoding"});
  next();
 },gateway);
}
