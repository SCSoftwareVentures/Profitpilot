// Fixed-schema per-process detection. Counts and category labels only;
// external aggregation and alert delivery remain separately deployed.
const rules=[
 {code:"auth_denial_spike",test:c=>c.authDenied+c.roleDenied>=20&&(c.authDenied+c.roleDenied)/Math.max(c.requests,1)>=0.2},
 {code:"actor_containment_spike",test:c=>c.actorContained>=5},
 {code:"rate_limit_spike",test:c=>c.rateLimited>=15},
 {code:"service_failure_spike",test:c=>c.unavailable+c.serverError>=5&&(c.unavailable+c.serverError)/Math.max(c.requests,1)>=0.1},
 {code:"slow_request_spike",test:c=>c.slow>=10&&c.slow/Math.max(c.requests,1)>=0.2},
 {code:"aborted_request_spike",test:c=>c.aborted>=15&&c.aborted/Math.max(c.requests,1)>=0.2}
];
export function createSecurityAlertPolicy(){
 const state=new Map(rules.map(r=>[r.code,{streak:0,active:false}]));
 return report=>{
  const alerts=[];
  for(const rule of rules){
   const item=state.get(rule.code);
   if(rule.test(report)){
    item.streak=Math.min(2,item.streak+1);
    if(item.streak>=2&&!item.active){item.active=true;alerts.push({event:"api_security_alert",category:rule.code,state:"active"});}
   }else{
    item.streak=0;
    if(item.active){item.active=false;alerts.push({event:"api_security_alert",category:rule.code,state:"cleared"});}
   }
  }
  return alerts;
 };
}
