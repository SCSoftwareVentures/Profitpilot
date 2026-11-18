// Test-only loopback courier; NOT a production transport adapter.
// Never run with real personal data, credentials, destinations or signing keys.
import {createServer,request} from "node:https";
import {checkServerIdentity} from "node:tls";
import {createHash,randomBytes,timingSafeEqual,X509Certificate} from "node:crypto";
import {privacyEnvelopeDigest,privacyKeyFingerprint} from "../../scripts/privacy-response-envelope.js";
import {verifyPrivacyReceiptChallenge,verifyPrivacyReceipt} from "../../scripts/privacy-delivery-receipt.js";
const HOST="127.0.0.1",MAX_RECEIPT=4096,MAX_PACKAGE=1500000;
const hash=x=>createHash("sha256").update(x).digest();
const exact=(x,k)=>x!==null&&typeof x==="object"&&!Array.isArray(x)&&Object.keys(x).length===k.length&&k.every(y=>Object.hasOwn(x,y));
const deny=()=>{throw Error("Synthetic privacy courier denied");};
const certHash=c=>hash(new X509Certificate(c).raw).toString("hex");
function respond(res,status,data){
 const body=JSON.stringify(data);
 res.writeHead(status,{"Content-Type":"application/json","Content-Length":Buffer.byteLength(body),"Cache-Control":"no-store","Pragma":"no-cache","X-Content-Type-Options":"nosniff","Connection":"close"});
 res.end(body);
}
export async function startSyntheticCourier({synthetic,expected,challenge,envelope,senderPublicKey,recipientSigningPublicKey,serverKey,serverCert,clientCert,clock=Date.now}){
 if(synthetic!==true||process.env.NODE_ENV==="production"||typeof clock!=="function")deny();
 // Freeze a detached snapshot of the approved package.
 expected=Object.freeze(structuredClone(expected));challenge=structuredClone(challenge);envelope=structuredClone(envelope);
 const validated=verifyPrivacyReceiptChallenge({challenge,expected,senderPublicKey,now:clock()});
 if(privacyEnvelopeDigest(envelope)!==expected.envelopeSha256||recipientSigningPublicKey?.asymmetricKeyType!=="ed25519"||
 privacyKeyFingerprint(recipientSigningPublicKey)!==expected.recipientSigningKeySha256)deny();
 let payload=JSON.stringify({envelope,challenge});
 if(Buffer.byteLength(payload)>MAX_PACKAGE)deny();
 const token=randomBytes(32).toString("hex"),tokenHash=hash(token),clientPin=certHash(clientCert);
 let state="ready",receiptEvidence=null,closed=false;
 function expire(){if(state!=="acknowledged"&&clock()>=validated.expiresAt){state="expired";payload=null;}}
 const server=createServer({key:serverKey,cert:serverCert,ca:clientCert,requestCert:true,rejectUnauthorized:true,minVersion:"TLSv1.3",maxHeaderSize:8192,requestTimeout:5000,headersTimeout:5000},(req,res)=>{
  const peer=req.socket.getPeerCertificate();
  const auth=req.headers.authorization;
  if(!req.socket.authorized||!peer?.raw||hash(peer.raw).toString("hex")!==clientPin||
  typeof auth!=="string"||!/^Bearer [a-f0-9]{64}$/.test(auth)||!timingSafeEqual(hash(auth.slice(7)),tokenHash)){
   req.resume();return respond(res,403,{error:"Denied"});
  }
  expire();
  if(req.method!=="POST"||!["/claim","/receipt"].includes(req.url)||req.headers["transfer-encoding"]!==undefined||
  req.headers["content-encoding"]!==undefined){req.resume();return respond(res,400,{error:"Denied"});}
  if(state==="expired"){req.resume();return respond(res,410,{error:"Expired"});}
  if(req.url==="/claim"){
   if(req.headers["content-length"]!=="0"){req.resume();return respond(res,400,{error:"Denied"});}
   if(state!=="ready"){req.resume();return respond(res,409,{error:"Conflict"});}
   // Consume the offer BEFORE writing. Lost network responses require a new
   // separately authorized release; never implicitly re-enable the claim.
   state="claimed";const body=payload;payload=null;
   res.writeHead(200,{"Content-Type":"application/json","Content-Length":Buffer.byteLength(body),"Cache-Control":"no-store","Pragma":"no-cache","X-Content-Type-Options":"nosniff","Connection":"close"});
   return res.end(body);
  }
  if(state!=="claimed"){req.resume();return respond(res,409,{error:"Conflict"});}
  const length=req.headers["content-length"];
  if(req.headers["content-type"]!=="application/json"||typeof length!=="string"||!/^[1-9][0-9]{0,3}$/.test(length)||Number(length)>MAX_RECEIPT){
   req.resume();return respond(res,400,{error:"Denied"});
  }
  let chunks=[],size=0,failed=false;
  req.on("data",chunk=>{size+=chunk.length;if(size>MAX_RECEIPT||size>Number(length)){failed=true;req.destroy();}else chunks.push(chunk);});
  req.on("error",()=>{failed=true;chunks=[];});
  req.on("end",()=>{
   if(failed||res.destroyed)return;
   expire();
   if(state==="expired")return respond(res,410,{error:"Expired"});
   if(state!=="claimed")return respond(res,409,{error:"Conflict"});
   try{
    if(size!==Number(length))deny();
    const raw=Buffer.concat(chunks);chunks=[];
    const receipt=JSON.parse(raw.toString("utf8"));
    // Require exact canonical JSON encoding; ambiguous/duplicate-key JSON
    // cannot be admitted as evidence.
    if(!Buffer.from(JSON.stringify(receipt),"utf8").equals(raw))deny();
    const evidence=verifyPrivacyReceipt({challenge,receipt,expected,senderPublicKey,recipientSigningPublicKey,now:clock()});
    if(evidence.challengeDigest!==validated.challengeDigest)deny();
    // No asynchronous gap between verification and single-use transition.
    receiptEvidence=evidence;state="acknowledged";
    return respond(res,200,evidence);
   }catch{return respond(res,403,{error:"Denied"});}
  });
 });
 // No arbitrary address, proxy, destination, external DNS or persistent data.
 await new Promise((resolve,reject)=>{server.once("error",reject);server.listen(0,HOST,()=>{server.off("error",reject);resolve();});});
 const port=server.address().port;
 return Object.freeze({port,token,serverPin:certHash(serverCert),
  status(){expire();return Object.freeze({state,receiptEvidence,deliveryVerified:false});},
  async close(){if(closed)return;closed=true;payload=null;server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
 });
}
// Client accepts only a numeric loopback port, exact test CA, pinned peer cert
// and caller-held mTLS key. No redirect handling, no proxy or URL input.
export async function syntheticCourierRequest({port,token,serverCert,serverPin,clientKey,clientCert,path,receipt}){
 if(!Number.isInteger(port)||port<1||port>65535||!["/claim","/receipt"].includes(path)||
 typeof token!=="string"||!/^[a-f0-9]{64}$/.test(token)||typeof serverPin!=="string"||!/^[a-f0-9]{64}$/.test(serverPin)||process.env.NODE_ENV==="production")deny();
 const body=path==="/claim"?Buffer.alloc(0):Buffer.from(JSON.stringify(receipt),"utf8");
 if(body.length>MAX_RECEIPT)deny();
 return new Promise((resolve,reject)=>{
  const req=request({hostname:HOST,port,path,method:"POST",key:clientKey,cert:clientCert,ca:serverCert,rejectUnauthorized:true,checkServerIdentity:(hostname,cert)=>checkServerIdentity(hostname,cert)||(!cert.raw||hash(cert.raw).toString("hex")!==serverPin?Error("Synthetic TLS peer pin mismatch"):undefined),minVersion:"TLSv1.3",agent:false,timeout:5000,headers:{Authorization:"Bearer "+token,"Content-Length":body.length,...(path==="/receipt"?{"Content-Type":"application/json"}:{})}},res=>{
   if(!res.socket.authorized||!res.socket.getPeerCertificate().raw||hash(res.socket.getPeerCertificate().raw).toString("hex")!==serverPin||
     res.statusCode>=300&&res.statusCode<400||res.headers["cache-control"]!=="no-store"){res.destroy();return reject(Error("Synthetic TLS response denied"));}
   let size=0;const chunks=[];
   res.on("data",chunk=>{size+=chunk.length;if(size>MAX_PACKAGE)res.destroy(Error("Synthetic TLS response exceeds bound"));else chunks.push(chunk);});
   res.on("error",reject);
   res.on("end",()=>{try{resolve({status:res.statusCode,data:JSON.parse(Buffer.concat(chunks).toString("utf8"))});}catch(e){reject(e);}});
  });
  // Check the actual peer before releasing either token or body. TLS verifies
  // hostname and CA as usual; a mismatched explicit pin aborts the request.
  req.on("socket",socket=>{socket.once("secureConnect",()=>{if(!socket.authorized||!socket.getPeerCertificate().raw||hash(socket.getPeerCertificate().raw).toString("hex")!==serverPin)req.destroy(Error("Synthetic TLS peer pin mismatch"));});});
  req.on("timeout",()=>req.destroy(Error("Synthetic TLS timeout")));req.on("error",reject);req.end(body);
 });
}
