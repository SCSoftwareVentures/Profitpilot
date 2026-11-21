// Aggregate-only G0 feasibility evaluator. Never grants a software build GO.
const SET_KEYS=["exportSetId","businessKey","period","bundleKey","authorized","complete","metrics"];
const METRIC_KEYS=["payrollPoolCents","payrollAttributableCents","invoiceEligibleCents","invoiceMatchedCents","customerMinutes","analystMinutes","rowCountsReconciled","monetaryTotalsReconciled","taxBasisDocumented","roundingDocumented","allocationBasisApproved","matchedEvidenceMediumHigh"];
const COMPETITION_KEYS=["productsTested","customerStacksTested","independentCustomerGaps","buyersConfirmingWillingness"];
function fail(message){throw Error("G0 input refused: "+message);}
function plain(value,allowed,label){
 if(value===null||typeof value!=="object"||Array.isArray(value)||Object.getPrototypeOf(value)!==Object.prototype)fail(label+" must be a plain object");
 const keys=Object.keys(value);
 if(keys.some(k=>!allowed.includes(k))||allowed.some(k=>!Object.hasOwn(value,k)))fail(label+" has unsupported or missing fields");
}
function nonnegative(n,label){if(!Number.isSafeInteger(n)||n<0)fail(label+" must be a nonnegative safe integer");}
function checkMetrics(value,index){
 if(value===null)return null;
 plain(value,METRIC_KEYS,"metrics "+index);
 for(const k of METRIC_KEYS.slice(0,6))nonnegative(value[k],"metric "+k);
 for(const k of METRIC_KEYS.slice(6))if(typeof value[k]!=="boolean")fail("metric "+k+" must be boolean");
 if(value.payrollAttributableCents>value.payrollPoolCents||value.invoiceMatchedCents>value.invoiceEligibleCents)fail("attributed or matched amount exceeds source total");
 return value;
}
const eighty=(part,whole)=>whole>0&&5n*BigInt(part)>=4n*BigInt(whole);
export function evaluateG0(packet){
 plain(packet,["sets","competition"],"packet");
 if(!Array.isArray(packet.sets)||packet.sets.length>100)fail("sets must be an array of at most 100");
 plain(packet.competition,COMPETITION_KEYS,"competition");
 for(const k of COMPETITION_KEYS){nonnegative(packet.competition[k],k);if(packet.competition[k]>1000)fail("competition count out of bounds");}
 const sets=packet.sets.map((s,i)=>{
  plain(s,SET_KEYS,"set "+i);
  for(const k of ["exportSetId","businessKey","bundleKey"])
   if(typeof s[k]!=="string"||!/^[A-Z0-9_-]{2,30}$/.test(s[k]))fail("set "+i+" needs a pseudonymous key");
  if(typeof s.period!=="string"||!/^20[0-9]{2}-(0[1-9]|1[0-2])$/.test(s.period))fail("set "+i+" has invalid period");
  if(typeof s.authorized!=="boolean"||typeof s.complete!=="boolean")fail("set "+i+" needs explicit flags");
  return {s,m:checkMetrics(s.metrics,i),fingerprint:JSON.stringify([s.businessKey,s.period,s.bundleKey])};
 });
 const ids=new Map(),bundles=new Map();
 for(const {s,fingerprint} of sets){
  ids.set(s.exportSetId,(ids.get(s.exportSetId)||0)+1);
  bundles.set(fingerprint,(bundles.get(fingerprint)||0)+1);
 }
 const businesses=new Set();let eligible=0,passing=0;
 const rows=sets.map(({s,m,fingerprint})=>{
  const duplicate=ids.get(s.exportSetId)>1||bundles.get(fingerprint)>1;
  const failedChecks=[];
  if(duplicate)failedChecks.push("duplicate_or_ambiguous_set");
  if(!s.authorized)failedChecks.push("authorization_not_declared");
  if(!s.complete)failedChecks.push("incomplete_bundle");
  let status="excluded";
  if(!duplicate&&s.authorized&&s.complete){
   eligible++;businesses.add(s.businessKey);
   if(m===null)failedChecks.push("metrics_missing");
   else{
    if(!eighty(m.payrollAttributableCents,m.payrollPoolCents))failedChecks.push("payroll_attribution_below_80_or_zero_pool");
    if(!eighty(m.invoiceMatchedCents,m.invoiceEligibleCents))failedChecks.push("evidence_matched_invoice_below_80_or_zero_value");
    if(m.customerMinutes>120)failedChecks.push("customer_minutes_over_120");
    if(m.analystMinutes>180)failedChecks.push("analyst_minutes_over_180");
    for(const [key,reason] of [
     ["rowCountsReconciled","row_counts_unreconciled"],
     ["monetaryTotalsReconciled","monetary_totals_unreconciled"],
     ["taxBasisDocumented","tax_basis_undocumented"],
     ["roundingDocumented","rounding_basis_undocumented"],
     ["allocationBasisApproved","allocation_basis_unapproved"],
     ["matchedEvidenceMediumHigh","match_evidence_not_medium_high"]
    ])if(!m[key])failedChecks.push(reason);
   }
   status=failedChecks.length?"measured_threshold_fail":"measured_threshold_pass";
   if(!failedChecks.length)passing++;
  }
  return {exportSetId:s.exportSetId,status,failedChecks};
 });
 const countsMet=eligible>=5&&businesses.size>=3;
 const shareMet=eligible>0&&5*passing>=4*eligible;
 const c=packet.competition;
 const competitorCountsMet=c.productsTested>=5&&c.customerStacksTested>=2&&c.independentCustomerGaps>=2&&c.buyersConfirmingWillingness>=1;
 return {
  schema:"profitpilot.g0.aggregate-feasibility.v1",
  scope:"pseudonymous_aggregate_claims_only",
  totalRecords:sets.length,uniqueCompleteAuthorizedRecords:eligible,distinctPseudonymousBusinesses:businesses.size,
  measuredThresholdPasses:passing,measuredThresholdFailures:eligible-passing,excludedRecords:sets.length-eligible,
  minimumExportAndBusinessCountsMet:countsMet,
  atLeast80PercentOfEligibleSetsMeetEveryThreshold:shareMet,
  competitiveDeclaredCountsMet:competitorCountsMet,
  numericClaimsMeetAllG0Thresholds:countsMet&&shareMet&&competitorCountsMet,
  independentlyVerified:false,demandValidated:false,
  g0Decision:"BLOCKED_PENDING_INDEPENDENT_EVIDENCE_REVIEW",softwareBuildAuthorized:false,rows
 };
}
