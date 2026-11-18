// Fixed-enum, non-identifying operational triage. Never grant authority or
// release a fence from telemetry. A healthy snapshot is not release approval.
export function securityResponsePlan(snapshot,now=Date.now()){
 const at=Date.parse(snapshot?.observedAt??"");
 const valid=Number.isFinite(now)&&Number.isFinite(at)&&at<=now+5000&&now-at<=120000;
 const response=(severity,category,action,notifyWithinMinutes)=>({event:"security_response_plan",severity,category,action,notifyWithinMinutes});
 if(!valid||snapshot?.catalogVerified!==true)
  return response("critical",valid?"catalog_drift":"snapshot_unavailable","keep_release_closed_and_escalate",5);
 const c=snapshot.counts;
 const fields=["activeTenantIncidents","temporarilyContainedActors","pendingOrRetryableScans","pendingOrProcessingPromotions","failedPromotions"];
 if(!c||fields.some(k=>!Number.isSafeInteger(c[k])||c[k]<0))return response("critical","snapshot_unavailable","keep_release_closed_and_escalate",5);
 if(c.activeTenantIncidents>0)return response("critical","tenant_containment","retain_tenant_fence_and_escalate",5);
 if(c.temporarilyContainedActors>=5)return response("high","actor_containment","retain_actor_controls_and_review",15);
 if(c.failedPromotions>0||c.pendingOrRetryableScans>=10||c.pendingOrProcessingPromotions>=10)
  return response("high","intake_anomaly","retain_intake_gate_and_review",15);
 return response("routine","observed","continue_monitoring",60);
}
