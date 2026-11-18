import test from "node:test";
import assert from "node:assert/strict";
import {invoiceIntakeFields} from "../src/invoice-intake.js";
const valid={controlTotal:"0.30",rowCount:2,evidenceDigest:"a".repeat(64)};
test("invoice materialization controls require exact positive cents, bounded count and evidence",()=>{
 assert.deepEqual(invoiceIntakeFields(valid),["0.30",2,"a".repeat(64)]);
 for(const c of [{controlTotal:0.30},{controlTotal:"0.3"},{controlTotal:"0.00"},{controlTotal:"-1.00"},{rowCount:0},{rowCount:201},{rowCount:"2"},{evidenceDigest:"0".repeat(64)},{extra:true}])assert.equal(invoiceIntakeFields({...valid,...c}),null);
});
