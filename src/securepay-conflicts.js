// SP-S4: syntax-only validation. Declarations are self-reported and NOT checked conflicts.
const uuid=x=>typeof x==="string"&&/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(x);
const reference=x=>typeof x==="string"&&/^[A-Za-z0-9][A-Za-z0-9._:-]{2,119}$/.test(x);
const conflictCodes=new Set(["financial_interest","personal_connection","prior_involvement","other"]);
const fields=["clientRequestId","declarationStatus","conflictCode","disclosureReference"];
export function validConflictDeclaration(b){
 if(!b||typeof b!=="object"||Array.isArray(b)||
  Object.keys(b).length!==fields.length||fields.some(k=>!Object.hasOwn(b,k))||!uuid(b.clientRequestId))return false;
 if(b.declarationStatus==="no_conflict_declared")
  return b.conflictCode===null&&b.disclosureReference===null;
 if(b.declarationStatus==="potential_conflict")
  return conflictCodes.has(b.conflictCode)&&reference(b.disclosureReference);
 return false;
}
export function sameConflictDeclaration(row,b){
 return row?.declaration_status===b.declarationStatus &&
  row?.conflict_code===b.conflictCode &&
  row?.disclosure_reference===b.disclosureReference;
}
