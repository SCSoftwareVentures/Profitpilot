// Minimize financial payloads at the ingestion boundary. Never echo excluded values.
const payroll={source_ref:120,cost_component:120,amount:32,currency:16,period_start:32,period_end:32};
const invoice={invoice_id:80,site:120,date:32,amount:32,currency:16,tax_basis:32,contract_id:64,site_id:64,service_start:32,service_end:32,description:500,line_number:16};
const schemas={payroll,customer_invoice:invoice,supplier_invoice:invoice};
export function importPayloadAllowed(sourceType,rows){
 if(!Object.hasOwn(schemas,sourceType)||!Array.isArray(rows)||rows.length<1||rows.length>200)return false;
 const fields=schemas[sourceType];
 return rows.every(row=>{
  if(!row||typeof row!=="object"||Array.isArray(row))return false;
  const entries=Object.entries(row);
  return entries.length>0&&entries.every(([key,value])=>{
   if(!Object.hasOwn(fields,key))return false;
   if(key==="line_number"&&Number.isSafeInteger(value))return value>=0&&value<=9999999;
   return typeof value==="string"&&value.length<=fields[key]&&!/[\x00-\x1f\x7f]/.test(value);
  });
 });
}
