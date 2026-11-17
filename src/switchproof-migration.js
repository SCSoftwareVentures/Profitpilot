import {money,isIsoDate} from "./engine.js";

const ID=/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SHA=/^[a-f0-9]{64}$/i;
const cents=value=>{const canonical=money(value);if(canonical===null)return null;const negative=canonical.startsWith("-");const unsigned=negative?canonical.slice(1):canonical;const [whole,fraction]=unsigned.split(".");const n=BigInt(whole)*100n+BigInt(fraction);return negative?-n:n;};
const format=value=>{const negative=value<0n,absolute=negative?-value:value;return (negative?"-":"")+String(absolute/100n)+"."+String(absolute%100n).padStart(2,"0")};

/**
 * Profile a synthetic or authorised in-memory source export before migration.
 * It does not copy, transform, persist or merge source records.
 */
export function profileMigration({manifest,mappings,requiredTargets,rows}={}){
  if(!manifest||typeof manifest!=="object"||Array.isArray(manifest))throw new TypeError("A source manifest is required.");
  if(!ID.test(manifest.sourceSystem||"")||!SHA.test(manifest.sourceSha256||"")||!ID.test(manifest.permissionReference||"")||
     !Number.isSafeInteger(manifest.expectedRowCount)||manifest.expectedRowCount<1||manifest.expectedRowCount>10000||
     !/^[A-Z]{3}$/.test(manifest.currency||"")||!["gst_inclusive","gst_exclusive","no_gst","unknown"].includes(manifest.taxBasis)||
     !isIsoDate(manifest.periodStart)||!isIsoDate(manifest.periodEnd)||manifest.periodEnd<manifest.periodStart){
    throw new TypeError("Source manifest identity, permission, checksum, row count, currency, tax basis and period must be explicit.");
  }
  if(!Array.isArray(mappings)||mappings.length===0||mappings.length>100||
     !Array.isArray(requiredTargets)||requiredTargets.length===0||
     !Array.isArray(rows)||rows.length>10000){
    throw new TypeError("Mappings, required targets and a bounded row array are required.");
  }
  const mapping=new Map();
  for(const item of mappings){
    if(!item||typeof item!=="object"||Array.isArray(item)||!ID.test(item.target||"")||!ID.test(item.source||"")||mapping.has(item.target)){
      throw new TypeError("Each mapping must contain unique safe target and source field identifiers.");
    }
    mapping.set(item.target,item.source);
  }
  if(requiredTargets.some(target=>typeof target!=="string"||!ID.test(target)||!mapping.has(target))){
    throw new TypeError("Every required target must have an explicit source mapping.");
  }
  const keyField=manifest.sourceKeyField;
  if(typeof keyField!=="string"||!ID.test(keyField)||!mapping.has("amount")||!mapping.has("date")||!mapping.has("currency")){
    throw new TypeError("Source row key, amount, date and currency mappings are mandatory.");
  }
  const seen=new Set(),exceptions=[];
  let parsedTotal=0n,validAmountRows=0;
  for(let index=0;index<rows.length;index++){
    const row=rows[index];
    if(!row||typeof row!=="object"||Array.isArray(row)){exceptions.push({rowNumber:index+1,code:"invalid_row"});continue;}
    const key=row[keyField];
    if(typeof key!=="string"||!ID.test(key.trim()))exceptions.push({rowNumber:index+1,code:"missing_or_invalid_source_key"});
    else if(seen.has(key.trim()))exceptions.push({rowNumber:index+1,code:"duplicate_source_key"});
    else seen.add(key.trim());
    for(const target of requiredTargets){
      const value=row[mapping.get(target)];
      if(value===undefined||value===null||(typeof value==="string"&&!value.trim()))exceptions.push({rowNumber:index+1,code:"missing_required_"+target});
    }
    const amount=cents(row[mapping.get("amount")]);
    if(amount===null)exceptions.push({rowNumber:index+1,code:"invalid_amount"});
    else{parsedTotal+=amount;validAmountRows++;}
    if(!isIsoDate(row[mapping.get("date")]))exceptions.push({rowNumber:index+1,code:"invalid_date"});
    if(row[mapping.get("currency")]!==manifest.currency)exceptions.push({rowNumber:index+1,code:"currency_mismatch"});
  }
  const countMatches=rows.length===manifest.expectedRowCount;
  if(!countMatches)exceptions.push({rowNumber:null,code:"source_row_count_mismatch"});
  const control=cents(manifest.controlTotal);
  const controlMatches=control!==null&&control===parsedTotal&&validAmountRows===rows.length;
  if(!controlMatches)exceptions.push({rowNumber:null,code:"source_control_total_mismatch"});
  const blockingCount=exceptions.length;
  return {
    sourceSystem:manifest.sourceSystem,
    sourceSha256:manifest.sourceSha256.toLowerCase(),
    mappingVersion:manifest.mappingVersion&&ID.test(manifest.mappingVersion)?manifest.mappingVersion:null,
    expectedRowCount:manifest.expectedRowCount,
    receivedRowCount:rows.length,
    validAmountRows,
    duplicateSourceKeys:exceptions.filter(x=>x.code==="duplicate_source_key").length,
    exceptionCount:blockingCount,
    exceptions,
    currency:manifest.currency,
    taxBasis:manifest.taxBasis,
    period:{start:manifest.periodStart,end:manifest.periodEnd},
    sourceControlTotal:control===null?null:format(control),
    parsedTotal:validAmountRows===rows.length?format(parsedTotal):null,
    controlTotalMatches,
    status:blockingCount===0?"ready_for_human_review":"blocked",
    migrationAccepted:false,
    automatedMerge:false,
    sourceDataCopied:false,
    limitations:[
      "This is a pre-migration profile only; it does not transform, persist or merge source data.",
      "A checksum and permission reference are caller-supplied metadata and are not independently verified here.",
      "A passing profile still requires human mapping approval, target-system reconciliation and an authorised migration."
    ]
  };
}
