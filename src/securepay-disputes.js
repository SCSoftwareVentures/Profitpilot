import {createHash} from 'node:crypto';

// SP-S1: synthetic-only deterministic dispute engine; no payments or live API.
// Role strings are NOT authentication. Authorisation and tenant RLS are future gates.
export const RESPONSE_DAYS=Object.freeze({low:2,medium:3,high:1});
const uuid=s=>typeof s==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(s);
const reference=s=>typeof s==='string'&&/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(s);
const instant=s=>typeof s==='string'&&/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(s)&&Number.isFinite(Date.parse(s));
const date=s=>typeof s==='string'&&/^\d{4}-\d\d-\d\d$/.test(s)&&Number.isFinite(Date.parse(s+'T12:00:00Z'))&&new Date(s+'T12:00:00Z').toISOString().slice(0,10)===s;
const sha=o=>createHash('sha256').update(JSON.stringify(o)).digest('hex');
const reject=s=>{throw new Error('SecurePay: '+s);};
const fields={classify:['severity','evidenceReference'],business_response:['evidenceReference'],
 offer_rectification:['proposedDueDate','evidenceReference'],agree_rectification:['evidenceReference'],
 set_rectification:['dueDate','impasseReference','evidenceReference'],
 rectification_result:['outcome','evidenceReference'],
 decide:['remedy','adjustmentCents','customerEvidenceReference','businessEvidenceReference','evidenceReference'],
 appeal:['evidenceReference'],resolve_appeal:['outcome','remedy','adjustmentCents','evidenceReference'],
 escalate:['reason','evidenceReference'],close:['evidenceReference']};
const statePart=s=>{const {events,lastHash,...rest}=s;return rest;};
const validActor=a=>a&&uuid(a.id)&&['customer','business','reviewer','admin'].includes(a.role);
export function localDate(at){
 if(!instant(at))reject('invalid UTC timestamp');
 const parts=Object.fromEntries(new Intl.DateTimeFormat('en-GB',{timeZone:'Australia/Melbourne',day:'2-digit',month:'2-digit',year:'numeric'}).formatToParts(new Date(at)).map(x=>[x.type,x.value]));
 return parts.year+'-'+parts.month+'-'+parts.day;
}
export function responseTarget({receivedAt,severity,calendar}){
 if(!instant(receivedAt)||!Object.hasOwn(RESPONSE_DAYS,severity))reject('invalid receipt or severity');
 const incomplete={businessDays:RESPONSE_DAYS[severity],dueLocalDate:null,timeZone:'Australia/Melbourne',calendarVerified:false};
 if(!calendar||calendar.timeZone!=='Australia/Melbourne'||calendar.verified!==true||
 !date(calendar.verifiedThrough)||!Array.isArray(calendar.holidays)||calendar.holidays.length>366||
 calendar.holidays.some(x=>!date(x))||new Set(calendar.holidays).size!==calendar.holidays.length)return incomplete;
 const d=new Date(localDate(receivedAt)+'T12:00:00Z'),holidays=new Set(calendar.holidays);
 let count=RESPONSE_DAYS[severity];
 while(count){d.setUTCDate(d.getUTCDate()+1);if(![0,6].includes(d.getUTCDay())&&!holidays.has(d.toISOString().slice(0,10)))count--;}
 const dueLocalDate=d.toISOString().slice(0,10);
 return calendar.verifiedThrough<dueLocalDate?incomplete:{...incomplete,dueLocalDate,calendarVerified:true};
}
function append(s,action){
 const e={sequence:s.events.length+1,previousHash:s.events.at(-1)?.hash??null,stateHash:sha(statePart(s)),...action};
 e.hash=sha(e);
 return {...s,events:[...s.events,e],lastHash:e.hash};
}
export function verifyDispute(s){
 if(!s||!uuid(s.id)||!uuid(s.tenantId)||!uuid(s.jobId)||!uuid(s.customerId)||!uuid(s.businessId)||
 s.customerId===s.businessId||!Array.isArray(s.events)||!s.events.length)return false;
 let prev=null;
 for(let i=0;i<s.events.length;i++){
  const e=s.events[i];if(!e||e.sequence!==i+1||e.previousHash!==prev||
  typeof e.hash!=='string'||!/^[a-f0-9]{64}$/.test(e.hash)||
  typeof e.stateHash!=='string'||!/^[a-f0-9]{64}$/.test(e.stateHash)||
  (i&&Date.parse(e.at)<Date.parse(s.events[i-1].at)))return false;
  const {hash,...unsigned}=e;if(sha(unsigned)!==hash)return false;prev=hash;
 }
 return s.lastHash===prev&&s.events.at(-1).stateHash===sha(statePart(s));
}
export function openDispute(input,actor){
 if(!input||typeof input!=='object'||Array.isArray(input)||
 Object.keys(input).some(k=>!['id','tenantId','jobId','customerId','businessId','submittedAt','claimReference','clientRequestId'].includes(k)))reject('unknown opening field');
 const {id,tenantId,jobId,customerId,businessId,submittedAt,claimReference,clientRequestId}=input;
 if([id,tenantId,jobId,customerId,businessId,clientRequestId].some(x=>!uuid(x))||
 customerId===businessId||!instant(submittedAt)||!reference(claimReference)||
 !validActor(actor)||actor.role!=='customer'||actor.id!==customerId)reject('invalid opening actor or scope');
 return append({id,tenantId,jobId,customerId,businessId,synthetic:true,fundsMoved:false,status:'awaiting_triage',
 severity:null,responseTarget:null,claimReference,businessResponseReference:null,
 rectification:null,decision:null,appeal:null,events:[],lastHash:null},
 {type:'opened',actorId:actor.id,actorRole:actor.role,at:submittedAt,clientRequestId,details:{claimReference}});
}
export function advanceDispute(s,{type,actor,at,clientRequestId,...input},calendar=null){
 if(!verifyDispute(s)||s.synthetic!==true||s.fundsMoved!==false)reject('invalid or altered case');
 if(!validActor(actor)||!instant(at)||!uuid(clientRequestId)||!Object.hasOwn(fields,type)||
 Object.keys(input).some(k=>!fields[type].includes(k))||
 Object.values(input).some(v=>v===undefined||v===null||typeof v==='object'))reject('invalid actor or action fields');
 if(Date.parse(at)<Date.parse(s.events.at(-1).at))reject('backdated event');
 const details=Object.fromEntries(Object.keys(input).sort().map(k=>[k,input[k]]));
 const replay=s.events.find(e=>e.clientRequestId===clientRequestId);
 if(replay){
  if(replay.type===type&&replay.actorId===actor.id&&replay.actorRole===actor.role&&replay.at===at&&
  JSON.stringify(replay.details)===JSON.stringify(details))return s;
  reject('conflicting idempotency key');
 }
 if(s.status==='closed')reject('closed case');
 const party=(role,id)=>actor.role===role&&actor.id===id;
 const reviewer=['reviewer','admin'].includes(actor.role)&&actor.id!==s.customerId&&actor.id!==s.businessId;
 const evidence=reference(input.evidenceReference);
 const next={...s};
 switch(type){
 case 'classify':
  if(!reviewer||!evidence||!Object.hasOwn(RESPONSE_DAYS,input.severity)||
   !['awaiting_triage','awaiting_business','under_review'].includes(s.status))reject('independent classification required');
  next.severity=input.severity;
  next.responseTarget=responseTarget({receivedAt:s.events[0].at,severity:input.severity,calendar});
  next.status=s.businessResponseReference?'under_review':'awaiting_business';break;
 case 'business_response':
  if(!party('business',s.businessId)||!evidence||s.businessResponseReference||
   !['awaiting_triage','awaiting_business'].includes(s.status))reject('invalid business reply');
  next.businessResponseReference=input.evidenceReference;
  next.status=s.severity?'under_review':'awaiting_triage';break;
 case 'offer_rectification':
  if(!party('business',s.businessId)||!evidence||!date(input.proposedDueDate)||
  input.proposedDueDate<=localDate(at)||!s.businessResponseReference||
  !['under_review','rectification_offered'].includes(s.status))reject('invalid rectification offer');
  next.rectification={deadline:input.proposedDueDate,source:'proposed',reference:input.evidenceReference};next.status='rectification_offered';break;
 case 'agree_rectification':
  if(!party('customer',s.customerId)||!evidence||s.status!=='rectification_offered')reject('customer consent required');
  next.rectification={...s.rectification,source:'agreed',agreementReference:input.evidenceReference};next.status='rectification';break;
 case 'set_rectification':
  if(!reviewer||!evidence||!reference(input.impasseReference)||!date(input.dueDate)||
  input.dueDate<=localDate(at)||!s.businessResponseReference||
  !['under_review','rectification_offered'].includes(s.status))reject('reviewer impasse decision required');
  next.rectification={deadline:input.dueDate,source:'independent_review',reference:input.evidenceReference,impasseReference:input.impasseReference};
  next.status='rectification';break;
 case 'rectification_result':
  if(!party('customer',s.customerId)||!evidence||s.status!=='rectification'||
  !['satisfactory','unsatisfactory'].includes(input.outcome))reject('customer rectification assessment required');
  next.rectification={...s.rectification,outcome:input.outcome,outcomeReference:input.evidenceReference};next.status='under_review';break;
 case 'decide':
  if(!reviewer||!evidence||s.status!=='under_review'||!s.severity||!s.businessResponseReference||
  !reference(input.customerEvidenceReference)||!reference(input.businessEvidenceReference)||
  !['full_without_deduction','partial_adjustment','refund_proposed','no_adjustment','other_lawful_remedy'].includes(input.remedy)||
  (input.remedy==='partial_adjustment'&&(!Number.isSafeInteger(input.adjustmentCents)||input.adjustmentCents<0))||
  (input.remedy!=='partial_adjustment'&&input.adjustmentCents!==undefined))reject('independent reasoned decision required');
  next.decision={reviewerId:actor.id,remedy:input.remedy,adjustmentCents:input.adjustmentCents??null,
  customerEvidenceReference:input.customerEvidenceReference,businessEvidenceReference:input.businessEvidenceReference,
  evidenceReference:input.evidenceReference,at};next.status='decided';break;
 case 'appeal':
  if(!(party('customer',s.customerId)||party('business',s.businessId))||
  !evidence||s.status!=='decided'||s.appeal)reject('invalid appeal');
  next.appeal={openedBy:actor.id,reasonReference:input.evidenceReference,reviewerId:null};next.status='appealed';break;
 case 'resolve_appeal':
  if(!reviewer||actor.id===s.decision?.reviewerId||!evidence||s.status!=='appealed'||
  !['upheld','revised'].includes(input.outcome)||
  (input.outcome==='revised'&&!['full_without_deduction','partial_adjustment','refund_proposed','no_adjustment','other_lawful_remedy'].includes(input.remedy))||
  (input.outcome==='revised'&&input.remedy==='partial_adjustment'&&(!Number.isSafeInteger(input.adjustmentCents)||input.adjustmentCents<0))||
  (input.outcome==='upheld'&&(input.remedy!==undefined||input.adjustmentCents!==undefined))||
  (input.outcome==='revised'&&input.remedy!=='partial_adjustment'&&input.adjustmentCents!==undefined))reject('independent appeal resolution required');
  next.appeal={...s.appeal,reviewerId:actor.id,outcome:input.outcome,evidenceReference:input.evidenceReference,
  remedy:input.outcome==='revised'?input.remedy:null,
  adjustmentCents:input.outcome==='revised'&&input.remedy==='partial_adjustment'?input.adjustmentCents:null};
  next.status='appeal_resolved';break;
 case 'escalate':
  if(!reviewer||!evidence||!['response_sla_missed','rectification_overdue','safety_risk','procedural_issue'].includes(input.reason))reject('manual escalation required');
  if(input.reason==='response_sla_missed'&&(!s.responseTarget?.calendarVerified||
  !s.responseTarget.dueLocalDate||localDate(at)<=s.responseTarget.dueLocalDate||s.businessResponseReference))reject('SLA not overdue');
  if(input.reason==='rectification_overdue'&&(!s.rectification||s.rectification.source==='proposed'||
  localDate(at)<=s.rectification.deadline))reject('rectification not overdue');
  break; // never authorises funds
 case 'close':
  if(!reviewer||!evidence||!['decided','appeal_resolved'].includes(s.status))reject('human decision required for closure');
  next.status='closed';break;
 default:reject('unsupported transition');
 }
 return append(next,{type,actorId:actor.id,actorRole:actor.role,at,clientRequestId,details});
}
