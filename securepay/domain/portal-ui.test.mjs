import test from "node:test";
import assert from "node:assert/strict";
import {Script,createContext} from "node:vm";
import {createHash,randomUUID} from "node:crypto";
import {customerPortalPage,ownerDashboardPage,customerQuotePage,ownerQuotePage,customerContractPage,ownerContractPage,customerCancellationPage,reviewerPage,disputeAdminPage,settlementAuthorizationPage,postAuthorizationPage,administratorSuccessionPage,participantPage} from "../../server/securepay-portal-page.js";
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

test("contract change customer screen only accepts current proposal after explicit consent",async()=>{
 const t=randomUUID(),p=randomUUID(),m=randomUUID(),v=randomUUID(),digest="a".repeat(64);
 const stage={milestoneId:m,amountCents:"5000",description:"Original scope",status:"planned",version:"0",final:true,eligible:true,terminalVerified:false};
 const change={changeId:v,kind:"variation",milestoneId:m,oldTotalCents:"5000",newTotalCents:"5500",newAmountCents:"5500",newDescription:"New scope",reason:"Mutually agreed new work",status:"offered",changeDigest:digest,current:true,affectedStages:[stage]};
 const contract={stateDigest:"b".repeat(64),state:{planId:p,originalTotalCents:"5000",effectiveTotalCents:"5000",stages:[stage]},changes:[change]};
 const response=x=>({code:200,data:{mode:"sandbox",moneyMoved:false,contract:x}});
 const h=ui(customerContractPage(),[response({...contract,changes:[{...change,current:false}]}),response(contract),{code:200,data:{mode:"sandbox",moneyMoved:false,status:"change_accepted",changeId:v}},response({...contract,changes:[{...change,status:"accepted",current:false}],state:{...contract.state,effectiveTotalCents:"5500",stages:[{...stage,amountCents:"5500",description:"New scope"}]}})]);
 h.get("tenant").value=t;h.get("plan").value=p;h.get("token").value="fixture";await h.fire("load");
 h.get("agree").checked=true;await h.fire("agree","change");assert.equal(h.get("accept").disabled,true);
 await h.fire("load");assert.equal(h.get("accept").disabled,true);
 h.get("agree").checked=true;await h.fire("agree","change");assert.equal(h.get("accept").disabled,false);
 await h.fire("accept");assert.deepEqual(JSON.parse(h.calls[2].opts.body),{changeId:v,changeDigest:digest,expectedTotalCents:5500});assert.equal(h.get("effective").textContent,"AUD $55.00");assert.equal(h.get("accept").disabled,true);
});
test("owner variation binds the loaded contract state digest and rejects ineligible stage",async()=>{
 const p=randomUUID(),m=randomUUID(),v=randomUUID(),stateDigest="c".repeat(64);
 const stage={milestoneId:m,amountCents:"5000",description:"Original scope",status:"planned",version:"0",final:true,eligible:true,terminalVerified:false};
 const contract={stateDigest,state:{planId:p,originalTotalCents:"5000",effectiveTotalCents:"5000",stages:[stage]},changes:[]};
 const reply=x=>({code:200,data:{mode:"sandbox",moneyMoved:false,contract:x}});
 const h=ui(ownerContractPage(),[reply(contract),{code:201,data:{mode:"sandbox",moneyMoved:false,change:{changeId:v}}},reply(contract)]);
 h.get("plan").value=p;h.get("token").value="fixture";await h.fire("load");
 h.get("kind").value="variation";h.get("reason").value="New negotiated scope";h.get("target").value=randomUUID();h.get("new-description").value="New scope";h.get("new-amount").value="60";
 await h.fire("offer");assert.equal(h.calls.length,1);
 h.get("target").value=m;await h.fire("offer");assert.equal(h.calls.length,3);
 assert.deepEqual(JSON.parse(h.calls[1].opts.body),{kind:"variation",reason:"New negotiated scope",stateDigest,milestoneId:m,newAmountCents:6000,newDescription:"New scope"});
});

test("funded cancellation customer consent resets on selection and never describes an accepted proposal as payment",async()=>{
 const t=randomUUID(),p=randomUUID(),m=randomUUID(),o=randomUUID(),digest="a".repeat(64);
 const offer={offerId:o,milestoneId:m,payoutCents:"500",refundCents:"1500",reason:"Agreed cancellation",offerDigest:digest,status:"offered",current:true,caseId:null,caseStatus:null,decision:null};
 const cancellation={planId:p,stages:[{milestoneId:m,amountCents:"2000",description:"First stage",status:"planned",stateDigest:digest}],offers:[offer],confirmedCancellationRefundCents:"0"};
 const reply=v=>({code:200,data:{mode:"sandbox",moneyMoved:false,cancellation:v}});
 const h=ui(customerCancellationPage(),[reply(cancellation),{code:200,data:{mode:"sandbox",moneyMoved:false,status:"negotiation_opened",caseId:randomUUID()}},reply({...cancellation,offers:[{...offer,status:"accepted",current:false}]})]);
 h.get("tenant").value=t;h.get("plan").value=p;h.get("token").value="fixture";await h.fire("load");
 h.get("agree").checked=true;await h.fire("agree","change");assert.equal(h.get("accept").disabled,true);
 h.get("offer-ref").value=o;await h.fire("offer-ref","input");assert.equal(h.get("agree").checked,false);assert.equal(h.get("accept").disabled,true);
 h.get("agree").checked=true;await h.fire("agree","change");assert.equal(h.get("accept").disabled,false);
 await h.fire("accept");assert.deepEqual(JSON.parse(h.calls[1].opts.body),{offerId:o,offerDigest:digest,payoutCents:500,refundCents:1500});assert.match(h.get("message").textContent,/No payment moved/);assert.equal(h.get("confirmed").textContent,"AUD $0.00");
});

test("reviewer page requires photo loading and explicit acknowledgement before binding exact decision snapshot",async()=>{
 const caseId=randomUUID(),photoId=randomUUID(),digest="a".repeat(64),stateDigest="b".repeat(64);
 const review={stateDigest,case:{caseId,severity:"moderate",status:"open",repairPhase:"none",amountCents:"5000",customerEvidence:true,ownerEvidence:true,firstReviewByMe:false,responseDueAt:"2026-11-20T06:00:00Z",events:[{at:"2026-11-19T06:00:00Z",role:"owner",action:"evidence",details:"<script>synthetic</script>",digest}],deadlines:[],photos:[{photoId,digest,purged:false,source:"dispute"}],linkedPhotos:[],linkedCompletions:[]}};
 const reply=x=>({code:200,data:{mode:"sandbox",moneyMoved:false,...x}});
 const h=ui(reviewerPage(),[reply({cases:[{caseId,severity:"moderate",status:"open",repairPhase:"none",dueAt:review.case.responseDueAt}]}),reply({review}),reply({photo:{photoId,digest,content:"aGVsbG8="}}),reply({status:"decision_recorded"}),reply({cases:[]})]);
 h.get("token").value="fixture";await h.fire("load");h.get("case-ref").value=caseId;await h.fire("open");
 assert.match(h.get("events").children[0].textContent,/<script>synthetic<\/script>/);
 h.get("action").value="decide";await h.fire("action","change");h.get("ack").checked=true;await h.fire("ack","change");assert.equal(h.get("submit").disabled,true);
 await h.fire("load-photos");assert.equal(h.get("ack").checked,false);assert.equal(h.get("submit").disabled,true);
 h.get("ack").checked=true;await h.fire("ack","change");assert.equal(h.get("submit").disabled,false);
 h.get("payout").value="30";h.get("refund").value="19.99";h.get("reason").value="Reasoned review of evidence";await h.fire("submit");assert.equal(h.calls.length,3);
 h.get("refund").value="20";await h.fire("submit");assert.deepEqual(JSON.parse(h.calls[3].opts.body),{caseId,action:"decide",reason:"Reasoned review of evidence",payoutCents:3000,refundCents:2000,stateDigest});
 assert.equal(h.get("details").hidden,true);assert.match(h.get("message").textContent,/No payment authorised/);
});

test("settlement dashboard binds explicit consent to the exact final decision and never reports money movement",async()=>{
 const caseId=randomUUID(),digest="a".repeat(64),review={stateDigest:digest,case:{caseId,caseStatus:"final",fundingStatus:"funded",amountCents:"5000",remainingCents:"5000",payoutCents:"3000",refundCents:"2000",independent:true,journalVerified:true,unresolved:false,decision:{reason:"Independent final decision",digest},legs:[]}};
 const response=x=>({code:200,data:{mode:"sandbox",moneyMoved:false,...x}});
 const h=ui(settlementAuthorizationPage(),[response({cases:[{caseId,severity:"moderate",status:"final",eligible:true,declared:true}]}),response({review}),response({status:"settlement_authorized",settlementId:randomUUID()}),response({cases:[]})]);
 h.get("token").value="fixture";await h.fire("load");h.get("case-ref").value=caseId;await h.fire("read");
 assert.equal(h.get("authorize").disabled,true);assert.match(h.get("summary").children[3].textContent,/AUD \$30.00/);
 h.get("agree").checked=true;await h.fire("agree","change");assert.equal(h.get("authorize").disabled,false);
 await h.fire("authorize");assert.deepEqual(JSON.parse(h.calls[2].opts.body),{caseId,payoutCents:3000,refundCents:2000,stateDigest:digest});assert.match(h.get("message").textContent,/No money moved/);assert.equal(h.get("authorize").disabled,true);
});
test("administrator case actions require rationale and exact actor identifier",async()=>{
 const caseId=randomUUID(),target=randomUUID(),response=x=>({code:200,data:{mode:"sandbox",moneyMoved:false,...x}}),h=ui(disputeAdminPage(),[response({cases:[]}),response({status:"recorded"}),response({cases:[]})]);
 h.get("token").value="fixture";await h.fire("load");h.get("case-ref").value=caseId;h.get("op").value="assign";h.get("target").value=target;h.get("reason").value="short";await h.fire("apply");assert.equal(h.calls.length,1);
 h.get("reason").value="Documented independent reviewer assignment";await h.fire("apply");assert.deepEqual(JSON.parse(h.calls[1].opts.body),{caseId,target,action:"assign",reason:"Documented independent reviewer assignment"});
});

test("reassessment screen requires second administrator and exact current request digest",async()=>{
 const caseId=randomUUID(),requestId=randomUUID(),stateDigest="a".repeat(64),request={caseId,requestId,stateDigest,reason:"Compromised reviewer",priorStatus:"final",priorPayoutCents:"3000",priorRefundCents:"2000",current:true,requestedByMe:false};
 const response=x=>({code:200,data:{mode:"sandbox",moneyMoved:false,...x}});
 const h=ui(disputeAdminPage(),[response({cases:[]}),response({requests:[{...request,requestedByMe:true}]}),response({requests:[request]}),response({reassessment:{requestId,status:"approved"}}),response({cases:[]}),response({requests:[]})]);
 h.get("token").value="fixture";await h.fire("load");h.get("case-ref").value=caseId;await h.fire("load-reassessments");
 h.get("request-ref").value=requestId;h.get("reassess-op").value="approve";h.get("reassess-reason").value="Independent verification of request";await h.fire("reassess");assert.equal(h.calls.length,2);
 await h.fire("load-reassessments");await h.fire("reassess");assert.deepEqual(JSON.parse(h.calls[3].opts.body),{caseId,requestId,stateDigest,action:"approve",reason:"Independent verification of request"});
 assert.match(h.get("message").textContent,/No payment moved/);
});

test("post-authorisation reviewer requires exact financial snapshot, evidence retrieval and explicit consent",async()=>{
 const caseId=randomUUID(),reviewId=randomUUID(),photoId=randomUUID(),digest="a".repeat(64),stateDigest="b".repeat(64),review={caseId,reviewId,status:"pending",reason:"New independent panel",payoutCents:"3000",refundCents:"2000",confirmedPayoutCents:"3000",confirmedRefundCents:"0",remainingCents:"2000",fundingStatus:"funded",journalVerified:true,panelCleared:true,safeToReaffirm:true,legs:[],events:[],photos:[{photoId,digest,purged:false,source:"dispute"}],linkedPhotos:[]};
 const response=x=>({code:200,data:{mode:"sandbox",moneyMoved:false,...x}});
 const h=ui(postAuthorizationPage("reviewer"),[response({postAuth:{review,stateDigest,votes:[]}}),response({photo:{photoId,digest,content:"aGVsbG8="}}),response({status:"review_recorded"})]);
 h.get("case-ref").value=caseId;h.get("token").value="fixture";h.get("outcome").value="reaffirm";await h.fire("load");
 h.get("confirm").checked=true;await h.fire("confirm","change");assert.equal(h.get("vote").disabled,true);
 await h.fire("load-photos");assert.equal(h.get("confirm").checked,false);h.get("confirm").checked=true;await h.fire("confirm","change");assert.equal(h.get("vote").disabled,false);
 h.get("vote-reason").value="Reviewed exact remaining allocation and photos";await h.fire("vote");
 assert.deepEqual(JSON.parse(h.calls[2].opts.body),{caseId,reviewId,stateDigest,outcome:"reaffirm",reason:"Reviewed exact remaining allocation and photos"});assert.match(h.get("message").textContent,/No payment moved/);
});
test("post-authorisation authoriser cannot reaffirm until both independent reviewers approve current state",async()=>{
 const caseId=randomUUID(),reviewId=randomUUID(),digest="c".repeat(64),review={caseId,reviewId,status:"pending",reason:"Independent panel",payoutCents:"3000",refundCents:"2000",confirmedPayoutCents:"0",confirmedRefundCents:"0",remainingCents:"5000",fundingStatus:"funded",journalVerified:true,panelCleared:true,safeToReaffirm:true,legs:[],events:[],photos:[],linkedPhotos:[]};
 const response=x=>({code:200,data:{mode:"sandbox",moneyMoved:false,...x}}),v={stage:"reviewer",outcome:"reaffirm",reason:"Independent review"};
 const h=ui(postAuthorizationPage("settlement"),[response({postAuth:{review,stateDigest:digest,votes:[v]}}),response({postAuth:{review,stateDigest:digest,votes:[v,v]}})]);
 h.get("case-ref").value=caseId;h.get("token").value="fixture";h.get("outcome").value="reaffirm";await h.fire("load");h.get("confirm").checked=true;await h.fire("confirm","change");assert.equal(h.get("vote").disabled,true);
 await h.fire("load");h.get("confirm").checked=true;await h.fire("confirm","change");assert.equal(h.get("vote").disabled,false);
});

test("succession dashboard refuses its own approval and requires current exact request plus separate consent",async()=>{
 const caseId=randomUUID(),requestId=randomUUID(),nominee=randomUUID(),stateDigest="a".repeat(64),previousAdmin=randomUUID(),q={caseId,requestId,nominee,stateDigest,previousAdmin,caseStatus:"final",reason:"Inactive administrator replacement",requestedByMe:false,current:true};
 const reply=x=>({code:200,data:{mode:"sandbox",moneyMoved:false,...x}});
 const h=ui(administratorSuccessionPage(),[reply({cases:[{...q,requestedByMe:true}]}),reply({cases:[q]}),reply({succession:{requestId,status:"approved"}}),reply({cases:[]})]);
 h.get("token").value="fixture";await h.fire("load");h.get("case-ref").value=caseId;h.get("request-ref").value=requestId;h.get("action").value="approve";h.get("reason").value="Independent verification of the replacement administrator";h.get("confirm").checked=true;await h.fire("confirm","change");
 await h.fire("submit");assert.equal(h.calls.length,1);
 await h.fire("load");assert.equal(h.get("submit").disabled,true);
 h.get("confirm").checked=true;await h.fire("confirm","change");await h.fire("submit");
 assert.deepEqual(JSON.parse(h.calls[2].opts.body),{caseId,requestId,nominee,stateDigest,action:"approve",reason:"Independent verification of the replacement administrator"});
 assert.match(h.get("message").textContent,/No payment moved/);
});

test("customer dispute screen requires exact repair image inspection and explicit current case consent",async()=>{
 const t=randomUUID(),m=randomUUID(),caseId=randomUUID(),photoId=randomUUID(),digest="a".repeat(64),stateDigest="b".repeat(64);
 const c={caseId,milestoneId:m,role:"customer",status:"open",severity:"moderate",repairPhase:"submitted",repairPhotoId:photoId,amountCents:"5000",confirmedPayoutCents:"0",confirmedRefundCents:"0",remainingCents:"5000",decision:null,events:[],photos:[{photoId,digest,source:"dispute",mine:false,purged:false}],linkedPhotos:[]};
 const view={case:c,stateDigest},reply=x=>({code:200,data:{mode:"sandbox",moneyMoved:false,participant:x}});
 const h=ui(participantPage("customer"),[reply(view),reply({photoId,digest,content:"aGVsbG8="}),reply({recorded:true}),reply({...view,case:{...c,repairPhase:"accepted"}})]);
 h.get("tenant").value=t;h.get("milestone").value=m;h.get("token").value="fixture";await h.fire("load");
 h.get("action").value="accept_repair";await h.fire("action","change");h.get("confirm").checked=true;await h.fire("confirm","change");assert.equal(h.get("submit").disabled,true);
 h.get("photo-ref").value=photoId;await h.fire("photo-ref","input");await h.fire("read-photo");assert.equal(h.get("confirm").checked,false);
 h.get("reason").value="Inspected the new repair evidence";await h.fire("reason","input");h.get("confirm").checked=true;await h.fire("confirm","change");assert.equal(h.get("submit").disabled,false);
 await h.fire("submit");assert.deepEqual(JSON.parse(h.calls[2].opts.body),{caseId,stateDigest,reason:"Inspected the new repair evidence",action:"accept_repair",dueEpoch:null,photoId});assert.match(h.get("message").textContent,/No payment moved/);
});
test("owner dispute screen binds proposed decision to exact amounts and clears case on uncertain submission",async()=>{
 const m=randomUUID(),caseId=randomUUID(),decisionId=randomUUID(),stateDigest="b".repeat(64),view={stateDigest,case:{caseId,milestoneId:m,role:"owner",status:"decided",severity:"moderate",repairPhase:"none",amountCents:"5000",confirmedPayoutCents:"0",confirmedRefundCents:"0",remainingCents:"5000",payoutCents:"3000",refundCents:"2000",decision:{eventId:decisionId,reason:"Independent assessment"},events:[],photos:[],linkedPhotos:[],ownerAck:false}};
 const h=ui(participantPage("owner"),[{code:200,data:{mode:"sandbox",moneyMoved:false,participant:view}},new Error("timeout")]);
 h.get("milestone").value=m;h.get("token").value="fixture";await h.fire("load");h.get("action").value="ack";await h.fire("action","change");h.get("reason").value="Consent to exact provisional decision";h.get("confirm").checked=true;await h.fire("confirm","change");await h.fire("submit");
 assert.deepEqual(JSON.parse(h.calls[1].opts.body),{caseId,stateDigest,reason:"Consent to exact provisional decision",decisionId,payoutCents:3000,refundCents:2000});
 assert.equal(h.get("details").hidden,true);assert.equal(h.get("submit").disabled,true);
});
