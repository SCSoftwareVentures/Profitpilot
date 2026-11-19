import test from "node:test";
import assert from "node:assert/strict";
import {Script,createContext} from "node:vm";
import {createHash,randomUUID} from "node:crypto";
import {customerPortalPage,ownerDashboardPage,customerQuotePage,ownerQuotePage} from "../../server/securepay-portal-page.js";
import {createPayerTokenVerifier} from "../../server/securepay-router.js";
import {generateKeyPair,SignJWT} from "jose";
function ui(page,responses){
 const nodes=new Map(),calls=[];
 function node(){
  return {value:"",checked:false,hidden:false,disabled:false,textContent:"",children:[],handlers:{},
   decode:async()=>{},addEventListener(name,fn){this.handlers[name]=fn;},append(...x){this.children.push(...x);},replaceChildren(){this.children=[];}};
 }
 const get=id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);};
 const script=page.html.match(/<script>([\s\S]*?)<\/script>/)[1];
 assert.ok(page.csp.includes("sha256-"+createHash("sha256").update(script).digest("base64")));
 const fetch=async(url,opts)=>{calls.push({url,opts});const r=responses.shift();if(r instanceof Error)throw r;assert.ok(r);return {status:r.code,ok:r.code>=200&&r.code<300,json:async()=>r.data};};
 new Script(script).runInContext(createContext({document:{getElementById:get,createElement:node},fetch,crypto:{randomUUID},BigInt,Number}));
 return {get,calls,fire:async(id,event="click")=>get(id).handlers[event]()};
}
test("customer portal holds approval until current exact funded milestone is reviewed and clears credentials on uncertainty",async()=>{
 const t=randomUUID(),m=randomUUID(),view={mode:"sandbox",moneyMoved:false,milestoneId:m,amountCents:"5000",status:"approved",fundingStatus:"funded",requestStatus:null};
 const h=ui(customerPortalPage(),[{code:200,data:view},new Error("timeout"),{code:200,data:{...view,status:"release_pending",requestStatus:"pending"}}]);
 h.get("tenant").value=t;h.get("milestone").value=m;h.get("token").value="fixture";
 await h.fire("load");assert.equal(h.get("amount").textContent,"AUD $50.00");assert.equal(h.get("token").value,"");assert.equal(h.get("reserve").disabled,true);
 h.get("confirm").checked=true;await h.fire("confirm","change");assert.equal(h.get("reserve").disabled,false);
 h.get("pin").value="012345";await h.fire("reserve");assert.equal(h.get("pin").value,"");assert.equal(h.get("reserve").disabled,true);assert.match(h.get("message").textContent,/uncertain/);
 assert.equal(h.calls.length,2);assert.equal(h.calls[1].url,"/v1/securepay/tenants/"+t+"/milestones/"+m+"/reserve");
 assert.equal(JSON.parse(h.calls[1].opts.body).expectedAmountCents,5000);
 await h.fire("load");assert.equal(h.get("reserve").disabled,true);
 await h.fire("clear");assert.equal(h.get("details").hidden,true);assert.equal(h.get("tenant").value,"");
});
test("portal scope edit invalidates approval and owner page safely renders text",async()=>{
 const t=randomUUID(),m=randomUUID(),h=ui(customerPortalPage(),[{code:200,data:{mode:"sandbox",moneyMoved:false,milestoneId:m,amountCents:"100",status:"approved",fundingStatus:"funded",requestStatus:null}}]);
 h.get("tenant").value=t;h.get("milestone").value=m;h.get("token").value="fixture";await h.fire("load");
 h.get("confirm").checked=true;await h.fire("confirm","change");assert.equal(h.get("reserve").disabled,false);
 h.get("milestone").value=randomUUID();await h.fire("milestone","input");assert.equal(h.get("reserve").disabled,true);assert.equal(h.get("details").hidden,true);
 const o=ui(ownerDashboardPage(),[{code:200,data:{report:{mode:"sandbox",moneyMoved:false,milestones:[{milestoneId:"<script>fixture</script>",status:"approved",fundingStatus:"funded",remainingCents:"100",journalVerified:true,unresolvedIssues:"0"}]},summary:{fundedCents:"100",payoutCents:"0",refundCents:"0",remainingCents:"100",mismatches:0,unresolvedIssues:"0",uncertainLegs:0,disputedMilestones:0}}}]);
 o.get("token").value="fixture";await o.fire("load");assert.equal(o.get("token").value,"");assert.equal(o.get("report").hidden,false);
 assert.equal(o.get("rows").children[0].children[0].textContent,"<script>fixture</script>");
 await o.fire("clear");assert.equal(o.get("report").hidden,true);
});
test("JWT verification denies mixed payer and owner audiences",async()=>{
 const {publicKey,privateKey}=await generateKeyPair("ES256"),issuer="https://fixture.invalid",audience="owner",acr="mfa";
 const verify=createPayerTokenVerifier({issuer,audience,requiredAcr:acr,keyResolver:publicKey});
 const make=aud=>new SignJWT({acr,auth_time:Math.floor(Date.now()/1000)}).setProtectedHeader({alg:"ES256"}).setIssuer(issuer).setAudience(aud).setSubject("owner-fixture").setIssuedAt().setExpirationTime("5m").sign(privateKey);
 assert.equal((await verify(await make("owner"))).subject,"owner-fixture");
 await assert.rejects(verify(await make(["owner","payer"])),/assurance/);
});

test("customer cannot approve until all completion images load and review is acknowledged",async()=>{
 const t=randomUUID(),m=randomUUID(),z=randomUUID(),p=randomUUID(),digest="a".repeat(64),manifest="b".repeat(64);
 const view={mode:"sandbox",moneyMoved:false,milestoneId:m,amountCents:"5000",status:"submitted",fundingStatus:"funded",requestStatus:null};
 const completion={mode:"sandbox",moneyMoved:false,completionId:z,manifestDigest:manifest,comments:"Completion notes",version:"1",amountCents:"5000",status:"submitted",photos:[{photoId:p,digest}]};
 const h=ui(customerPortalPage(),[{code:200,data:view},{code:200,data:completion},{code:200,data:{mode:"sandbox",moneyMoved:false,photoId:p,digest,content:"aGVsbG8="}},{code:200,data:{mode:"sandbox",moneyMoved:false,status:"work_approved"}}]);
 h.get("tenant").value=t;h.get("milestone").value=m;h.get("token").value="fixture";await h.fire("load");
 assert.equal(h.get("reserve").disabled,true);assert.equal(h.get("approve-work").disabled,true);
 await h.fire("load-evidence");assert.equal(h.get("evidence").children.length,1);assert.equal(h.get("approve-work").disabled,true);
 h.get("inspect").checked=true;await h.fire("inspect","change");assert.equal(h.get("approve-work").disabled,false);
 await h.fire("approve-work");
 assert.deepEqual(JSON.parse(h.calls[3].opts.body),{completionId:z,manifestDigest:manifest,expectedAmountCents:5000,version:"1"});
 assert.equal(h.get("details").hidden,true);assert.equal(h.get("reserve").disabled,true);
});

test("customer agreement explicitly binds consent to loaded quote and exact cent amount",async()=>{
 const t=randomUUID(),p=randomUUID(),digest="a".repeat(64),quote={mode:"sandbox",moneyMoved:false,planId:p,quote:{description:"Synthetic work scope",revision:2,totalCents:"5000"},totalCents:"5000",planDigest:digest,status:"offered",items:[{milestoneId:randomUUID(),description:"Full work",amountCents:5000,final:true}]};
 const h=ui(customerQuotePage(),[{code:200,data:quote},{code:200,data:{mode:"sandbox",moneyMoved:false,planId:p,status:"plan_accepted"}}]);
 h.get("tenant").value=t;h.get("plan").value=p;h.get("token").value="fixture";await h.fire("load");
 assert.equal(h.get("total").textContent,"AUD $50.00");assert.equal(h.get("description").textContent,"Synthetic work scope");assert.equal(h.get("accept").disabled,true);
 h.get("agree").checked=true;await h.fire("agree","change");assert.equal(h.get("accept").disabled,false);
 await h.fire("accept");assert.deepEqual(JSON.parse(h.calls[1].opts.body),{planDigest:digest,expectedTotalCents:5000});assert.equal(h.get("accept").disabled,true);assert.equal(h.get("details").hidden,true);
});
test("owner quote screen refuses mismatched stage totals and locks accepted quote revisions",async()=>{
 const job=randomUUID(),digest="b".repeat(64),planId=randomUUID(),view={jobId:job,quote:{quoteDigest:digest,revision:1,description:"Approved scope",totalCents:"5000"},plan:null};
 const h=ui(ownerQuotePage(),[{code:200,data:{mode:"sandbox",moneyMoved:false,view}},{code:201,data:{mode:"sandbox",moneyMoved:false,planId}},{code:200,data:{mode:"sandbox",moneyMoved:false,view:{...view,plan:{planId,status:"accepted"}}}}]);
 h.get("job").value=job;h.get("token").value="fixture";await h.fire("load");
 h.get("stage-description").value="First stage";h.get("stage-amount").value="20.00";await h.fire("add");await h.fire("offer");assert.equal(h.calls.length,1);assert.match(h.get("message").textContent,/must equal/);
 h.get("stage-description").value="Last stage";h.get("stage-amount").value="30";await h.fire("add");await h.fire("offer");assert.equal(h.calls.length,3);
 const sent=JSON.parse(h.calls[1].opts.body);assert.equal(sent.quoteDigest,digest);assert.deepEqual(sent.items.map(x=>[x.amountCents,x.final]),[[2000,false],[3000,true]]);
 assert.equal(h.get("publish").disabled,true);assert.equal(h.get("withdraw").disabled,true);
});
