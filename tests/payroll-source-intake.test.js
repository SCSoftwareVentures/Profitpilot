import test from "node:test";
import assert from "node:assert/strict";
import {createHash,randomUUID} from "node:crypto";
import {inspectMinimizedPayroll} from "../src/payroll-source-intake.js";
const H=x=>createHash("sha256").update(x).digest("hex"),key=i=>"ppr_"+H("synthetic row "+i);
const rows=[key(1)+",0.10,AUD",key(2)+",0.20,AUD"],header="source_row_key,amount,currency\n";
const fixture=(body=rows.join("\n")+"\n",changes={})=>{
 const bytes=Buffer.from(header+body);return {bytes,manifest:{format:"minimized-payroll-v1",sourceNamespace:randomUUID(),periodStart:"2026-11-01",periodEnd:"2026-11-14",currency:"AUD",controlTotal:"0.30",rowCount:2,fileSha256:H(bytes),authorityDigest:H("authority"),policyDigest:H("policy"),controlDigest:H("control"),...changes}};
};
test("canonical minimized payroll amounts reconcile exactly and require independent approval",()=>{
 const f=fixture(),out=inspectMinimizedPayroll(f.bytes,f.manifest);assert.equal(out.status,"pending_independent_review");assert.equal(out.requiresHumanConfirmation,true);assert.deepEqual(out.source.rows,[{source_row_key:key(1),amount:"0.10",currency:"AUD"},{source_row_key:key(2),amount:"0.20",currency:"AUD"}]);
});
for(const [name,body,changes] of [
 ["employee identifier","employee-123,0.10,AUD\n"+rows[1]+"\n",{}],
 ["additional personal column",rows[0]+",synthetic@example.invalid\n"+rows[1]+"\n",{}],
 ["duplicates",rows[0]+"\n"+key(1)+",0.20,AUD\n",{}],
 ["negative source",key(1)+",-0.10,AUD\n"+rows[1]+"\n",{}],
 ["mixed currency",key(1)+",0.10,USD\n"+rows[1]+"\n",{}],
 ["noncanonical decimals",key(1)+",0.1,AUD\n"+rows[1]+"\n",{}],
 ["scientific notation",key(1)+",1e-1,AUD\n"+rows[1]+"\n",{}],
 ["formula",key(1)+",=0.10,AUD\n"+rows[1]+"\n",{}],
 ["leading zeros",key(1)+",00.10,AUD\n"+rows[1]+"\n",{}],
 ["Unicode",key(1)+",０.10,AUD\n"+rows[1]+"\n",{}],
 ["CRLF",rows.join("\r\n")+"\r\n",{}],
 ["missing newline",rows.join("\n"),{}],
 ["extra row",rows.join("\n")+"\n"+key(3)+",0.00,AUD\n",{}],
 ["control mismatch",undefined,{controlTotal:"0.31"}],
 ["checksum mismatch",undefined,{fileSha256:H("other")}],
 ["extra manifest field",undefined,{employee:"not allowed"}],
 ["wrong source currency",undefined,{currency:"USD"}],
 ["unknown format",undefined,{format:"unsupported"}],
 ["invalid period",undefined,{periodEnd:"2026-02-30"}],
 ["zero authority digest",undefined,{authorityDigest:"0".repeat(64)}],
 ["numeric total",undefined,{controlTotal:0.3}],
 ["oversize row count",undefined,{rowCount:201}],
 ["reversed period",undefined,{periodEnd:"2026-01-01"}]
])test("reject "+name+" without echoing input",()=>{const f=fixture(body,changes),out=inspectMinimizedPayroll(f.bytes,f.manifest);assert.equal(out.status,"held");assert.equal(out.source,null);assert.deepEqual(Object.keys(out).sort(),["code","requiresHumanConfirmation","source","status"]);});
test("maximum supported money uses exact cents; pool overflow rejected",()=>{
 const f=fixture(key(1)+",999999999999.99,AUD\n"+key(2)+",0.00,AUD\n",{controlTotal:"999999999999.99"});
 assert.equal(inspectMinimizedPayroll(f.bytes,f.manifest).status,"pending_independent_review");
 const overflow=fixture(key(1)+",999999999999.99,AUD\n"+key(2)+",0.01,AUD\n",{controlTotal:"1000000000000.00"});
 assert.equal(inspectMinimizedPayroll(overflow.bytes,overflow.manifest).status,"held");
});
