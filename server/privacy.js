// Structural privacy boundary for client-declared rows. No unknown fields or nested personal data.
const columns={
 payroll:new Set(["source_ref","amount","currency","period_start","period_end"]),
 customer_invoice:new Set(["invoice_id","site","date","amount"]),
 supplier_invoice:new Set(["invoice_id","site","date","amount"])
};
export function allowedImportRows(rows,sourceType){
 const allowed=columns[sourceType];
 if(!(allowed instanceof Set)||!Array.isArray(rows))return false;
 return rows.every(row=>row&&typeof row==="object"&&!Array.isArray(row)&&
 Object.keys(row).length>0&&Object.entries(row).every(([key,value])=>allowed.has(key)&&
 (value===null||(typeof value==="string"&&value.length<=1000&&!/[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]/u.test(value)))));
}
