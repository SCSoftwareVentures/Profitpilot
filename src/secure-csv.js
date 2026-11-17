// CSV is the only binary request format accepted by the financial import endpoint.
// No paths, archives, markup, macros, dynamic evaluation or file persistence.
import {createHash} from "node:crypto";
import {importPayloadAllowed} from "./import-privacy.js";
const MAX_BYTES=100*1024,MAX_ROWS=200,MAX_COLS=12,MAX_CELL=500;
const fail=error=>({error});
export function parseFinancialCsv(bytes,sourceType){
 if(!(bytes instanceof Buffer)||Buffer.byteLength(bytes)<1||Buffer.byteLength(bytes)>MAX_BYTES)return fail("Invalid CSV size");
 let text;
 try{text=new TextDecoder("utf-8",{fatal:true}).decode(bytes);}catch{return fail("CSV must be valid UTF-8");}
 if(/[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]/.test(text))return fail("CSV contains prohibited control characters");
 // Strict record parser, including quoted commas and escaped quotes. No multiline cells.
 let rows=[],row=[],cell="",state="start";
 function pushCell(){if(cell.length>MAX_CELL||row.length>=MAX_COLS)return false;row.push(cell);cell="";state="start";return true;}
 function pushRow(){if(!pushCell()||rows.length>=MAX_ROWS+1)return false;rows.push(row);row=[];return true;}
 for(let i=0;i<text.length;i++){
  const c=text[i];
  if(c==="\r"||c==="\n"){
   if(state==="quoted"||c==="\r"&&text[i+1]!=="\n")return fail("Multiline or malformed CSV");
   if(c==="\r")i++;
   if(!pushRow())return fail("CSV exceeds row or column bounds");
   continue;
  }
  if(state==="quoted"){
   if(c==='"'){if(text[i+1]==='"'){cell+='"';i++;}else state="closed";}
   else cell+=c;
  }else if(c===","){if(!pushCell())return fail("CSV exceeds field bounds");}
  else if(c==='"'){if(state!=="start")return fail("Malformed CSV quote");state="quoted";}
  else {if(state==="closed")return fail("Unexpected content after quoted field");state="plain";cell+=c;}
  if(cell.length>MAX_CELL)return fail("CSV exceeds field bounds");
 }
 if(state==="quoted")return fail("Unclosed CSV quote");
 if(row.length||cell.length||state!=="start"){if(!pushRow())return fail("CSV exceeds row bounds");}
 if(rows.length<2)return fail("A header and at least one source row are required");
 const headers=rows.shift();
 if(headers.some(h=>!h||h!==h.trim())||new Set(headers).size!==headers.length)return fail("Invalid or duplicate CSV headings");
 const records=[];
 for(const cells of rows){
  if(cells.length!==headers.length)return fail("Inconsistent CSV field count");
  const entries=headers.map((h,i)=>{
   const v=cells[i];
   return [h,h==="line_number"&&/^[1-9][0-9]{0,6}$/.test(v)?Number(v):v];
  });
  // Treat every untrusted text cell as data, never a spreadsheet expression.
  if(entries.some(([h,v])=>h!=="amount"&&typeof v==="string"&&/^\s*[=+@-]/.test(v)))return fail("Formula-like text is prohibited in CSV imports");
  records.push(Object.fromEntries(entries));
 }
 if(!importPayloadAllowed(sourceType,records))return fail("CSV contains unsupported or excessive source fields");
 return {rows:records,sha256:createHash("sha256").update(bytes).digest("hex")};
}
