import {createHash} from "node:crypto";
export const MAX_SOURCE_BYTES=512*1024;
export const MAX_SOURCE_ROWS=2000;
const headersByType={
 payroll:["source_ref","amount","currency","period_start","period_end"],
 customer_invoice:["invoice_id","site","date","amount"],
 supplier_invoice:["invoice_id","site","date","amount"]
};
export function parseSourceFile(bytes,sourceType){
 if(!Buffer.isBuffer(bytes)||!bytes.length||bytes.length>MAX_SOURCE_BYTES)throw new Error("CSV size outside supported bounds");
 const expected=headersByType[sourceType];
 if(!Array.isArray(expected))throw new Error("Unsupported source type");
 let text;
 try{text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);}catch{throw new Error("CSV must be valid UTF-8");}
 if(/[\x00-\x09\x0B\x0C\x0E-\x1F\x7F-\x9F\u202A-\u202E\u2066-\u2069]/u.test(text))throw new Error("CSV contains disallowed control characters");
 const records=[];let row=[],field="",state="start";
 function cell(){
  if(field.length>1000)throw new Error("CSV field exceeds limit");
  row.push(field);field="";state="start";
  if(row.length>expected.length)throw new Error("CSV column count exceeds schema");
 }
 function record(){
  cell();
  if(row.length!==expected.length)throw new Error("CSV row width does not match schema");
  records.push(row);row=[];
  if(records.length>MAX_SOURCE_ROWS+1)throw new Error("CSV row limit exceeded");
 }
 for(let i=0;i<text.length;i++){
  const ch=text[i];
  if(state==="quoted"){
   if(ch==='"'){
    if(text[i+1]==='"'){field+='"';i++;}else state="closed";
   }else field+=ch;
  }else if(ch===","){cell();}
  else if(ch==="\n"||ch==="\r"){
   if(ch==="\r"){if(text[i+1]!=="\n")throw new Error("Invalid CSV line ending");i++;}
   record();
  }else if(state==="closed"){throw new Error("Unexpected character after quoted CSV field");}
  else if(ch==='"'){if(state!=="start")throw new Error("Unexpected quote in CSV field");state="quoted";}
  else {field+=ch;state="plain";}
  if(field.length>1000)throw new Error("CSV field exceeds limit");
 }
 if(state==="quoted")throw new Error("Unclosed CSV quote");
 if(row.length||field.length||state!=="start")record();
 if(records.length<2)throw new Error("CSV requires a header and at least one row");
 const header=records.shift();
 if(new Set(header).size!==expected.length||expected.some(h=>!header.includes(h)))throw new Error("CSV header does not match allowed source schema");
 for(const cells of records)for(const value of cells){
  const trimmed=value.trimStart();
  if(/^[=+@]/.test(trimmed)||(/^-/.test(trimmed)&&!/^-\d+(?:\.\d{1,2})?$/.test(trimmed)))throw new Error("Potential spreadsheet formula rejected");
 }
 return {sha256:createHash("sha256").update(bytes).digest("hex"),rows:records.map(c=>Object.fromEntries(header.map((h,i)=>[h,c[i]])))};
}
